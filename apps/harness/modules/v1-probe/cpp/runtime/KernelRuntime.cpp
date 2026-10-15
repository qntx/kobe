#include "KernelRuntime.hpp"

#include "KernelBuffer.hpp"
#include "KernelGlobals.hpp"

#if defined(__ANDROID__)
#include "platform/KernelPbkdf2.hpp"
#include <fbjni/fbjni.h>
#include <jni.h>
#endif

#include <condition_variable>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <thread>

#if defined(__APPLE__) || defined(__ANDROID__)
#include <pthread.h>
#endif

namespace qntx {

namespace jsi = facebook::jsi;

namespace {

std::string describe(const std::exception_ptr& error) {
  try {
    std::rethrow_exception(error);
  } catch (const jsi::JSError& e) {
    std::string message = e.getMessage();
    const std::string& stack = e.getStack();
    if (!stack.empty()) {
      message += "\n" + stack;
    }
    // The jsi::Value inside JSError references a Hermes PointerValue whose
    // scope ended while the exception unwound out of evaluateJavaScript;
    // running ~JSError would call PointerValue::invalidate() on freed
    // memory. Retain the exception for the process lifetime: this path is
    // terminal for the runtime, so the leak is bounded to one JSError per
    // crashed kernel.
    static auto* retained = new std::vector<std::exception_ptr>();
    retained->push_back(error);
    return "jsi::JSError: " + message;
  } catch (const std::exception& e) {
    return std::string(e.what());
  } catch (...) {
    return "unknown error";
  }
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
  hermes::vm::RuntimeConfig config;
  std::shared_ptr<KernelGlobalsState> globals;

  std::mutex mutex;
  std::condition_variable cv;
  bool stopping = false;
  std::deque<std::function<void()>> immediate;
  struct Timed {
    std::shared_ptr<std::atomic_bool> cancelled;
    jsi::Function fn;
  };
  std::multimap<std::chrono::steady_clock::time_point, Timed> timed;

  // Kernel thread only.
  std::unique_ptr<jsi::Runtime> rt;
  std::optional<std::string> fatal;

  std::thread thread;
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
    const hermes::vm::RuntimeConfig& config,
    KernelScript script,
    Hooks hooks) {
  if (script.bytes == nullptr || script.bytes->empty()) {
    throw std::invalid_argument("KernelRuntime::start: empty script");
  }
  auto self = std::shared_ptr<KernelRuntime>(new KernelRuntime());
  auto& impl = *self->impl_;
  impl.config = config;
  impl.script = std::move(script);
  impl.hooks = std::move(hooks);
  impl.globals = std::make_shared<KernelGlobalsState>();
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
  impl.thread = std::thread([self]() mutable {
    self->impl_->run();
    self.reset();
  });
  return self;
}

bool KernelRuntime::running() const noexcept {
  return impl_->running.load(std::memory_order_acquire);
}

void KernelRuntime::post(std::vector<uint8_t> bytes) {
  auto& impl = *impl_;
  {
    std::lock_guard<std::mutex> lock(impl.mutex);
    if (impl.stopping || !impl.running.load(std::memory_order_acquire)) {
      return;
    }
    impl.immediate.push_back(
        [&impl, bytes = std::move(bytes)]() mutable { impl.deliver(std::move(bytes)); });
  }
  impl.cv.notify_one();
}

void KernelRuntime::destroy() {
  auto& impl = *impl_;
  {
    std::lock_guard<std::mutex> lock(impl.mutex);
    impl.stopping = true;
  }
  impl.cv.notify_all();
  if (!impl.thread.joinable()) {
    return;
  }
  if (std::this_thread::get_id() == impl.thread.get_id()) {
    // Called from the kernel thread (e.g. inside a hook): let the loop tear
    // down on its own; the thread owns the last shared_ptr until it exits.
    impl.thread.detach();
    return;
  }
  impl.thread.join();
}

void KernelRuntime::Impl::run() {
  nameKernelThread();
  auto work = [this] {
    try {
      initRuntime();
      loop();
    } catch (...) {
      fail("kernel thread failed: " + describe(std::current_exception()));
    }
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
  rt = facebook::hermes::makeHermesRuntime(config);
  installKernelGlobals(*rt, globals);

  // Hermes' InternalBytecode promise machinery defers internal work through
  // the host's setImmediate/setTimeout (or the engine job queue) and the
  // rejection tracker surfaces unhandled rejections via the same deferral.
  // A bare runtime has neither, so provide minimal versions backed by the
  // kernel task queue. Without them Promise rejection tracking (and, under
  // the hardened config, Promise itself) throws ReferenceError.
  static const char* kKernelPrelude =
      "(function () {\n"
      "  var timers = {};\n"
      "  var nextId = 0;\n"
      "  function schedule(fn, ms) {\n"
      "    var id = ++nextId;\n"
      "    timers[id] = __qntx.setTimer(ms > 0 ? ms : 0, fn);\n"
      "    return id;\n"
      "  }\n"
      "  function cancel(id) {\n"
      "    var c = timers[id];\n"
      "    if (c !== undefined) {\n"
      "      delete timers[id];\n"
      "      c();\n"
      "    }\n"
      "  }\n"
      "  if (typeof globalThis.setImmediate !== 'function') {\n"
      "    globalThis.setImmediate = function (fn) {\n"
      "      return schedule(fn, 0);\n"
      "    };\n"
      "    globalThis.clearImmediate = cancel;\n"
      "  }\n"
      "  if (typeof globalThis.setTimeout !== 'function') {\n"
      "    globalThis.setTimeout = function (fn, ms) {\n"
      "      return schedule(fn, ms);\n"
      "    };\n"
      "    globalThis.clearTimeout = cancel;\n"
      "  }\n"
      "  if (typeof globalThis.queueMicrotask !== 'function') {\n"
      "    globalThis.queueMicrotask = function (fn) {\n"
      "      Promise.resolve().then(fn);\n"
      "    };\n"
      "  }\n"
      "})();\n"
      "if (typeof HermesInternal === 'object' && HermesInternal !== null && "
      "typeof HermesInternal.enablePromiseRejectionTracker === 'function') {\n"
      "  HermesInternal.enablePromiseRejectionTracker({\n"
      "    allRejections: true,\n"
      "    onHandled: function () {},\n"
      "    onUnhandled: function (id, reason) {\n"
      "      __qntxUnhandledRejection(\n"
      "        id,\n"
      "        reason == null\n"
      "          ? 'unknown'\n"
      "          : String(reason && reason.stack ? reason.stack : reason)\n"
      "      );\n"
      "    },\n"
      "  });\n"
      "}\n";
  rt->evaluateJavaScript(
      std::make_shared<jsi::StringBuffer>(kKernelPrelude), "<kernel-init>");

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
    std::optional<Timed> due;
    {
      std::unique_lock<std::mutex> lock(mutex);
      for (;;) {
        if (stopping) {
          lock.unlock();
          teardown();
          return;
        }
        const auto now = std::chrono::steady_clock::now();
        if (!timed.empty() && timed.begin()->first <= now) {
          due = std::move(timed.extract(timed.begin()).mapped());
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

    try {
      if (task) {
        task();
      } else if (due.has_value() && !due->cancelled->load(std::memory_order_relaxed)) {
        due->fn.call(*rt);
      }
      rt->drainMicrotasks();
    } catch (...) {
      // Drop jsi values before teardown destroys the runtime they belong to.
      due.reset();
      task = nullptr;
      fail("kernel task failed: " + describe(std::current_exception()));
      return;
    }
    if (fatal.has_value()) {
      due.reset();
      task = nullptr;
      fail(*fatal);
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
    immediate.push_back(
        [this, task = std::move(task)]() mutable { task(*rt); });
  }
  cv.notify_one();
}

KernelGlobalsState::TimerCancel KernelRuntime::Impl::scheduleTimer(
    std::chrono::steady_clock::time_point deadline,
    jsi::Function fn) {
  auto cancelled = std::make_shared<std::atomic_bool>(false);
  {
    std::lock_guard<std::mutex> lock(mutex);
    if (stopping) {
      cancelled->store(true, std::memory_order_relaxed);
    } else {
      timed.emplace(deadline, Timed{cancelled, std::move(fn)});
    }
  }
  cv.notify_one();
  return cancelled;
}

void KernelRuntime::Impl::fail(std::string message) {
  // Kernel thread only.
  {
    std::lock_guard<std::mutex> lock(mutex);
    stopping = true;
  }
  if (hooks.onError) {
    try {
      hooks.onError(std::move(message));
    } catch (...) {
    }
  }
  teardown();
}

void KernelRuntime::Impl::teardown() {
  // Kernel thread only: drop every jsi value before the runtime itself.
  globals->messageHandler.reset();
  for (const auto& call : globals->pending) {
    call->done.reset();
  }
  globals->pending.clear();
  {
    std::lock_guard<std::mutex> lock(mutex);
    timed.clear();
    immediate.clear();
  }
  rt.reset();
  running.store(false, std::memory_order_release);
}

} // namespace qntx
