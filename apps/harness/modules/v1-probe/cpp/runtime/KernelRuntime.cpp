#include "KernelRuntime.hpp"

#include "KernelBuffer.hpp"
#include "KernelGlobals.hpp"

#include <jsi/hermes-interfaces.h>

#if defined(__ANDROID__)
#include "platform/KernelPbkdf2.hpp"
#include <fbjni/fbjni.h>
#include <jni.h>
#endif

#include <atomic>
#include <condition_variable>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <thread>
#include <unordered_map>
#include <utility>

#if defined(__APPLE__) || defined(__ANDROID__)
#include <pthread.h>
#endif

namespace qntx {

namespace jsi = facebook::jsi;

namespace {

// Turns the current exception into a description. Called only inside catch
// blocks so the exception_ptr — and any jsi values a JSError holds — die
// while the runtime that owns them is still alive.
std::string describe(const std::exception_ptr& error) {
  try {
    std::rethrow_exception(error);
  } catch (const jsi::JSError& e) {
    std::string message = e.getMessage();
    const std::string& stack = e.getStack();
    if (!stack.empty()) {
      message += "\n" + stack;
    }
    return "jsi::JSError: " + message;
  } catch (const std::exception& e) {
    return std::string(e.what());
  } catch (...) {
    return "unknown error";
  }
}

hermes::vm::RuntimeConfig runtimeConfigFor(KernelProfile profile) {
  auto builder = profile == KernelProfile::hardened
      ? facebook::hermes::hardenedHermesRuntimeConfig().rebuild()
      : hermes::vm::RuntimeConfig::Builder();
  return builder.withMicrotaskQueue(true)
      .withEnableEval(false)
      .withAsyncBreakCheckInEval(true)
      .build();
}

void nameKernelThread() {
#if defined(__APPLE__)
  pthread_setname_np("qntx-kernel");
#elif defined(__ANDROID__)
  pthread_setname_np(pthread_self(), "qntx-kernel");
#endif
}

} // namespace

struct KernelRuntime::Impl {
  KernelScript script;
  Hooks hooks;
  KernelProfile profile = KernelProfile::standard;
  std::shared_ptr<KernelGlobalsState> globals;

  // Guards `immediate`, and the `stopping` store in destroy() so the loop's
  // cv predicate can never miss a wakeup.
  std::mutex mutex;
  std::condition_variable cv;
  std::deque<std::function<void()>> immediate;

  std::atomic_bool stopping{false};

  // Publishes the live runtime's IHermes so destroy() can interrupt running
  // JS. The kernel thread sets it after makeHermesRuntime and withdraws it
  // under the same mutex BEFORE rt.reset(), so asyncTriggerTimeout can never
  // touch a destroyed runtime.
  std::mutex interruptMutex;
  facebook::hermes::IHermes* interruptable = nullptr;

  std::mutex stoppedMutex;
  std::condition_variable stoppedCv;
  bool stopped = false;

  // Kernel thread only.
  std::unique_ptr<jsi::Runtime> rt;
  std::optional<std::string> fatal;
  struct Timer {
    uint64_t id;
    jsi::Function fn;
  };
  using TimedMap = std::multimap<std::chrono::steady_clock::time_point, Timer>;
  TimedMap timed;
  std::unordered_map<uint64_t, TimedMap::iterator> timerIndex;
  uint64_t nextTimerId = 0;

  // Read and written only under `mutex`: enqueue() may run on the KDF worker
  // thread while teardown() runs on the kernel thread.
  bool tornDown = false;

  std::atomic_bool running{false};

  void run();
  void initRuntime();
  void evaluate();
  void loop();
  void fail(std::string message);
  void teardown();
  void deliver(std::vector<uint8_t> bytes);
  // Queues a task that runs fn(rt) on the kernel thread. Accepts work even
  // after `stopping`: queued-but-unrun tasks are destroyed by teardown, which
  // runs before the runtime itself is destroyed — so jsi values captured by
  // tasks are always released on the kernel thread while the runtime lives.
  void enqueue(std::function<void(jsi::Runtime&)> task);
  KernelGlobalsState::TimerCancel scheduleTimer(
      std::chrono::steady_clock::time_point deadline,
      jsi::Function fn);
};

KernelRuntime::KernelRuntime() : impl_(std::make_shared<Impl>()) {}

KernelRuntime::~KernelRuntime() {
  destroy();
}

std::shared_ptr<KernelRuntime> KernelRuntime::start(
    KernelScript script,
    Hooks hooks,
    KernelProfile profile) {
  if (script.bytes == nullptr || script.bytes->empty()) {
    throw std::invalid_argument("KernelRuntime::start: empty script");
  }
  auto self = std::shared_ptr<KernelRuntime>(new KernelRuntime());
  auto& impl = *self->impl_;
  impl.profile = profile;
  impl.script = std::move(script);
  impl.hooks = std::move(hooks);
  impl.globals = std::make_shared<KernelGlobalsState>();
  impl.globals->active = std::make_shared<std::atomic_bool>(true);
  impl.globals->postToHost = impl.hooks.onPost;
  impl.globals->reportFatal = [&impl](std::string message) {
    impl.fatal = std::move(message);
  };
  impl.globals->scheduleTimer =
      [&impl](std::chrono::steady_clock::time_point deadline, jsi::Function fn) {
        return impl.scheduleTimer(deadline, std::move(fn));
      };
  // Async completions (e.g. pbkdf2) may arrive after the KernelRuntime object
  // is destroyed, so reach the impl through a weak_ptr instead of a reference.
  std::weak_ptr<Impl> weakImpl = self->impl_;
  impl.globals->enqueueTask =
      [weakImpl](std::function<void(jsi::Runtime&)> task) mutable {
        if (auto impl = weakImpl.lock()) {
          impl->enqueue(std::move(task));
        }
      };
  impl.running.store(true, std::memory_order_release);
  // The detached thread holds the Impl, not the KernelRuntime: dropping the
  // last public handle just requests shutdown through ~KernelRuntime →
  // destroy(), and the kernel thread finishes teardown on its own.
  std::thread([impl = self->impl_]() { impl->run(); }).detach();
  return self;
}

bool KernelRuntime::running() const noexcept {
  return impl_->running.load(std::memory_order_acquire);
}

bool KernelRuntime::waitUntilStopped(std::chrono::milliseconds timeout) const {
  auto& impl = *impl_;
  std::unique_lock<std::mutex> lock(impl.stoppedMutex);
  return impl.stoppedCv.wait_for(lock, timeout, [&] { return impl.stopped; });
}

void KernelRuntime::post(std::vector<uint8_t> bytes) {
  auto& impl = *impl_;
  {
    std::lock_guard<std::mutex> lock(impl.mutex);
    if (impl.stopping.load(std::memory_order_acquire) ||
        !impl.running.load(std::memory_order_acquire)) {
      return;
    }
    impl.immediate.push_back(
        [&impl, bytes = std::move(bytes)]() mutable { impl.deliver(std::move(bytes)); });
  }
  impl.cv.notify_one();
}

void KernelRuntime::destroy() noexcept {
  auto& impl = *impl_;
  {
    std::lock_guard<std::mutex> lock(impl.mutex);
    if (impl.stopping.load(std::memory_order_acquire)) {
      return;
    }
    impl.stopping.store(true, std::memory_order_release);
  }
  impl.cv.notify_all();
  {
    std::lock_guard<std::mutex> lock(impl.interruptMutex);
    if (impl.interruptable != nullptr) {
      impl.interruptable->asyncTriggerTimeout();
    }
  }
}

void KernelRuntime::Impl::run() {
  nameKernelThread();
  auto work = [this] {
    std::optional<std::string> error;
    try {
      initRuntime();
      loop();
    } catch (...) {
      // describe() runs inside the catch so a JSError (and the jsi values it
      // holds) is destroyed while the runtime still exists.
      try {
        error = describe(std::current_exception());
      } catch (...) {
        error = "undescribable kernel error";
      }
    }
    // An exception raised after a destroy() request — the async interrupt or
    // anything racing it — is a normal stop, not a kernel failure.
    if (error.has_value() && !stopping.load(std::memory_order_acquire)) {
      fail(std::move(*error));
    }
    teardown();
  };
#if defined(__ANDROID__)
  // Run the kernel body inside a Java call frame via fbjni. A plain
  // AttachCurrentThread gives the thread a JNIEnv but FindClass still resolves
  // through the boot class loader, which cannot see app-dex classes — Hermes
  // delegates String.prototype.normalize/localeCompare to
  // com.facebook.hermes.unicode.AndroidUnicodeUtils, and Nitro's registry is a
  // Java class; the former throws fbjni::JniException across a noexcept
  // boundary (std::terminate) on a raw attached thread. WithClassLoader makes
  // app classes resolvable and attaches the thread for the whole duration.
  facebook::jni::ThreadScope::WithClassLoader(std::move(work));
#else
  work();
#endif
}

void KernelRuntime::Impl::initRuntime() {
  rt = facebook::hermes::makeHermesRuntime(runtimeConfigFor(profile));
  {
    std::lock_guard<std::mutex> lock(interruptMutex);
    interruptable = jsi::castInterface<facebook::hermes::IHermes>(rt.get());
  }
  if (interruptable == nullptr) {
    throw std::runtime_error("hermes runtime does not expose IHermes");
  }
  if (stopping.load(std::memory_order_acquire)) {
    // destroy() won the race before the script ran: skip globals and
    // evaluation; run() then returns from loop() at once into teardown.
    return;
  }

  installKernelGlobals(*rt, globals);

  if (hooks.beforeEvaluate) {
    hooks.beforeEvaluate(*rt);
  }

  evaluate();
  rt->drainMicrotasks();
  if (fatal.has_value()) {
    throw std::runtime_error(*fatal);
  }
}

void KernelRuntime::Impl::evaluate() {
  const auto& bytes = *script.bytes;
  if (script.kind == KernelScript::Kind::bytecode) {
    auto* api = jsi::castInterface<facebook::hermes::IHermesRootAPI>(
        facebook::hermes::makeHermesRootAPI());
    if (api == nullptr) {
      throw std::runtime_error("Hermes root API unavailable");
    }
    if (!api->isHermesBytecode(bytes.data(), bytes.size())) {
      throw std::runtime_error("embedded code is not Hermes bytecode");
    }
    std::string sanityError;
    if (!api->hermesBytecodeSanityCheck(bytes.data(), bytes.size(), &sanityError)) {
      throw std::runtime_error(
          "embedded Hermes bytecode failed sanity check (version " +
          std::to_string(api->getBytecodeVersion()) + "): " + sanityError);
    }
    rt->evaluateJavaScript(
        std::make_shared<VectorBuffer>(script.bytes), "kernel.hbc");
  } else {
    rt->evaluateJavaScript(
        std::make_shared<jsi::StringBuffer>(
            std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size())),
        "kernel.ts");
  }
}

void KernelRuntime::Impl::loop() {
  for (;;) {
    std::function<void()> task;
    std::optional<Timer> due;
    {
      std::unique_lock<std::mutex> lock(mutex);
      for (;;) {
        if (stopping.load(std::memory_order_acquire)) {
          return;
        }
        const auto now = std::chrono::steady_clock::now();
        // Timers live on the kernel thread only; the mutex here just happens
        // to be held while picking the next piece of work.
        if (!timed.empty() && timed.begin()->first <= now) {
          auto node = timed.extract(timed.begin());
          timerIndex.erase(node.mapped().id);
          due = std::move(node.mapped());
          break;
        }
        if (!immediate.empty()) {
          task = std::move(immediate.front());
          immediate.pop_front();
          break;
        }
        if (timed.empty()) {
          cv.wait(lock);
        } else {
          cv.wait_until(lock, timed.begin()->first);
        }
      }
    }

    std::optional<std::string> error;
    try {
      if (task) {
        task();
      } else if (due.has_value()) {
        due->fn.call(*rt);
      }
      rt->drainMicrotasks();
    } catch (...) {
      error = describe(std::current_exception());
    }
    // Drop jsi values while the runtime is alive, whichever way we exit.
    due.reset();
    task = nullptr;
    if (error.has_value()) {
      if (stopping.load(std::memory_order_acquire)) {
        // The destroy() interrupt surfaced as an exception — a normal stop.
        return;
      }
      fail("kernel task failed: " + std::move(*error));
      return;
    }
    if (fatal.has_value()) {
      fail(std::move(*fatal));
      return;
    }
  }
}

void KernelRuntime::Impl::deliver(std::vector<uint8_t> bytes) {
  if (!globals->messageHandler.has_value()) {
    return;
  }
  auto buffer = rt->createArrayBuffer(std::make_shared<OwningBuffer>(std::move(bytes)));
  globals->messageHandler->call(*rt, jsi::Value(std::move(buffer)));
}

void KernelRuntime::Impl::enqueue(std::function<void(jsi::Runtime&)> task) {
  {
    std::lock_guard<std::mutex> lock(mutex);
    if (tornDown) {
      // The loop is gone and teardown already ran: drop the task here so its
      // captures (wiping buffers, dead pending calls) release immediately.
      return;
    }
    immediate.push_back(
        [this, task = std::move(task)]() mutable { task(*rt); });
  }
  cv.notify_one();
}

KernelGlobalsState::TimerCancel KernelRuntime::Impl::scheduleTimer(
    std::chrono::steady_clock::time_point deadline,
    jsi::Function fn) {
  // Kernel thread only — host functions and the loop run there, so no lock.
  const uint64_t id = nextTimerId++;
  auto it = timed.emplace(deadline, Timer{id, std::move(fn)});
  timerIndex.emplace(id, it);
  return [this, id] {
    if (tornDown) {
      return;
    }
    auto found = timerIndex.find(id);
    if (found != timerIndex.end()) {
      // Erasing releases the stored jsi::Function immediately instead of
      // parking it until the deadline.
      timed.erase(found->second);
      timerIndex.erase(found);
    }
  };
}

void KernelRuntime::Impl::fail(std::string message) {
  // Kernel thread only.
  stopping.store(true, std::memory_order_release);
  if (hooks.onError) {
    try {
      hooks.onError(std::move(message));
    } catch (...) {
    }
  }
  teardown();
}

void KernelRuntime::Impl::teardown() {
  // Kernel thread only; tornDown is shared with enqueue() on other threads,
  // so it is set under the same mutex that guards the queue.
  {
    std::lock_guard<std::mutex> lock(mutex);
    if (tornDown) {
      return;
    }
    tornDown = true;
    // Queued-but-unrun tasks die here, on the kernel thread, while the
    // runtime is alive; enqueue() drops anything that arrives after this.
    immediate.clear();
  }
  // Drop every jsi value before the runtime itself.
  globals->intrinsics.reset();
  globals->messageHandler.reset();
  for (const auto& call : globals->pending) {
    call->done.reset();
  }
  globals->pending.clear();
  // A KDF worker that sees inactive drops its job — safe only because `done`
  // was already cleared above, on this thread, while the runtime was alive.
  globals->active->store(false, std::memory_order_release);
  // Timed/timerIndex are kernel-thread-only state.
  timed.clear();
  timerIndex.clear();
  {
    std::lock_guard<std::mutex> lock(interruptMutex);
    interruptable = nullptr;
  }
  rt.reset();
  running.store(false, std::memory_order_release);
  {
    std::lock_guard<std::mutex> lock(stoppedMutex);
    stopped = true;
  }
  stoppedCv.notify_all();
}

} // namespace qntx
