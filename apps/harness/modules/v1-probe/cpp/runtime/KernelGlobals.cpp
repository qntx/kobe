#include "KernelGlobals.hpp"

#include "KernelBuffer.hpp"
#include "platform/KernelPbkdf2.hpp"

#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>

#if defined(__APPLE__) || defined(__ANDROID__)
#include <pthread.h>
#include <unistd.h>
#elif defined(__linux__)
#include <cerrno>
#include <sys/random.h>
#include <unistd.h>
#endif

#if defined(__ANDROID__)
#include <fbjni/fbjni.h>
#endif

namespace qntx {

// Captured JS intrinsics, taken on the pristine runtime before any script can
// tamper with the builtins they come from. Every member is a jsi value owned
// by the kernel thread; teardown resets the holding shared_ptr while the
// runtime is still alive.
struct KernelIntrinsics {
  jsi::Function defineProperty;
  jsi::Function freeze;
  jsi::Function typeError;
  jsi::Function uint8Array;
  // The real %TypedArray%.prototype accessors. Calling them reads internal
  // slots, so forged objects throw and redefined prototype getters cannot lie.
  jsi::Function taBufferGet;
  jsi::Function taByteOffsetGet;
  jsi::Function taByteLengthGet;
  jsi::Function taTagGet;
};

namespace {

constexpr size_t kRandomLimit = 65536;
constexpr double kTimerDelayMax = 2147483647.0;
constexpr double kPbkdf2IterationsMax = 10000000.0;
constexpr size_t kPbkdf2LengthMax = 1024;
constexpr size_t kKdfQueueLimit = 8;

jsi::Function hostFn(
    jsi::Runtime& rt,
    const char* name,
    unsigned int paramCount,
    jsi::HostFunctionType fn) {
  return jsi::Function::createFromHostFunction(
      rt, jsi::PropNameID::forAscii(rt, name), paramCount, std::move(fn));
}

void fillRandom(uint8_t* out, size_t size) {
#if defined(__APPLE__) || defined(__ANDROID__)
  arc4random_buf(out, size);
#elif defined(__linux__)
  size_t filled = 0;
  while (filled < size) {
    const ssize_t got = getrandom(out + filled, size - filled, 0);
    if (got < 0) {
      if (errno == EINTR) {
        continue;
      }
      std::abort();
    }
    filled += static_cast<size_t>(got);
  }
#else
#error "kernel runtime: no platform random source"
#endif
}

double finiteNumber(jsi::Runtime& rt, const jsi::Value& value, const char* name) {
  if (!value.isNumber() || !std::isfinite(value.getNumber())) {
    throw jsi::JSError(rt, std::string(name) + " expects a finite number");
  }
  return value.getNumber();
}

uint64_t integerInRange(
    jsi::Runtime& rt,
    const jsi::Value& value,
    const char* name,
    double min,
    double max) {
  const double n = finiteNumber(rt, value, name);
  if (n < min || n > max || std::floor(n) != n) {
    throw jsi::JSError(rt, std::string(name) + " is out of range");
  }
  return static_cast<uint64_t>(n);
}

// A view into a live ArrayBuffer: `buffer` keeps the storage referenced while
// `data`/`size` are borrowed from it.
struct ByteView {
  jsi::ArrayBuffer buffer;
  uint8_t* data;
  size_t size;
};

// The shared extractor for every byte input (pbkdf2 password/salt,
// decodeUtf8, getRandomValues). Accepts a real ArrayBuffer or a genuine
// TypedArray — identified by calling the captured %TypedArray%.prototype
// getters, which read internal slots: forged plain objects throw TypeError and
// a redefined Uint8Array.prototype getter cannot lie.
ByteView byteViewFromValue(
    jsi::Runtime& rt,
    const jsi::Value& value,
    const char* name,
    const KernelIntrinsics& intrinsics) {
  if (!value.isObject()) {
    throw jsi::JSError(rt, std::string(name) + " expects an ArrayBuffer or TypedArray");
  }
  auto object = value.asObject(rt);
  if (object.isArrayBuffer(rt)) {
    auto buffer = object.getArrayBuffer(rt);
    uint8_t* data = buffer.data(rt);
    const size_t size = buffer.size(rt);
    return {std::move(buffer), data, size};
  }
  const jsi::Value bufferValue =
      intrinsics.taBufferGet.callWithThis(rt, object);
  const jsi::Value offsetValue =
      intrinsics.taByteOffsetGet.callWithThis(rt, object);
  const jsi::Value lengthValue =
      intrinsics.taByteLengthGet.callWithThis(rt, object);
  if (!bufferValue.isObject() || !bufferValue.asObject(rt).isArrayBuffer(rt)) {
    throw jsi::JSError(rt, std::string(name) + " view is not backed by an ArrayBuffer");
  }
  const double offset = finiteNumber(rt, offsetValue, "byteOffset");
  const double length = finiteNumber(rt, lengthValue, "byteLength");
  if (offset < 0 || std::floor(offset) != offset ||
      length < 0 || std::floor(length) != length) {
    throw jsi::JSError(rt, std::string(name) + " view bounds must be non-negative integers");
  }
  auto buffer = bufferValue.asObject(rt).getArrayBuffer(rt);
  uint8_t* data = buffer.data(rt);
  const size_t bufferSize = buffer.size(rt);
  if (offset + length > static_cast<double>(bufferSize)) {
    throw jsi::JSError(rt, std::string(name) + " view exceeds its ArrayBuffer");
  }
  return {std::move(buffer), data + static_cast<size_t>(offset), static_cast<size_t>(length)};
}

[[noreturn]] void throwTypeError(
    jsi::Runtime& rt,
    const KernelIntrinsics& intrinsics,
    const char* message) {
  auto error = intrinsics.typeError.callAsConstructor(
      rt, jsi::Value(rt, jsi::String::createFromAscii(rt, message)));
  throw jsi::JSError(rt, jsi::Value(std::move(error)));
}

// WHATWG UTF-8 decode: valid sequences are copied verbatim; with fatal=false
// each maximal subpart of an ill-formed sequence becomes one U+FFFD; fatal=true
// throws TypeError. A leading BOM is stripped unless ignoreBOM.
std::vector<uint8_t> decodeUtf8Bytes(
    jsi::Runtime& rt,
    const KernelIntrinsics& intrinsics,
    const uint8_t* data,
    size_t size,
    bool fatal,
    bool ignoreBOM) {
  if (!ignoreBOM && size >= 3 && data[0] == 0xef && data[1] == 0xbb && data[2] == 0xbf) {
    data += 3;
    size -= 3;
  }
  std::vector<uint8_t> out;
  out.reserve(size);
  size_t i = 0;
  while (i < size) {
    const uint8_t b0 = data[i];
    if (b0 < 0x80) {
      out.push_back(b0);
      i += 1;
      continue;
    }
    size_t expected;
    uint8_t lo = 0x80;
    uint8_t hi = 0xbf;
    if (b0 >= 0xc2 && b0 <= 0xdf) {
      expected = 2;
    } else if (b0 == 0xe0) {
      expected = 3;
      lo = 0xa0;
    } else if (b0 == 0xed) {
      expected = 3;
      hi = 0x9f;
    } else if (b0 >= 0xe1 && b0 <= 0xef) {
      expected = 3;
    } else if (b0 == 0xf0) {
      expected = 4;
      lo = 0x90;
    } else if (b0 == 0xf4) {
      expected = 4;
      hi = 0x8f;
    } else if (b0 >= 0xf1 && b0 <= 0xf3) {
      expected = 4;
    } else {
      if (fatal) {
        throwTypeError(rt, intrinsics, "TextDecoder: input is not valid UTF-8");
      }
      out.push_back(0xef);
      out.push_back(0xbf);
      out.push_back(0xbd);
      i += 1;
      continue;
    }
    // Maximal subpart: consume the lead byte plus the longest valid prefix of
    // continuation bytes (the second byte carries the overlong/surrogate range
    // restriction; later bytes accept 80..BF).
    size_t consumed = 1;
    if (i + 1 < size && data[i + 1] >= lo && data[i + 1] <= hi) {
      consumed = 2;
      while (consumed < expected && i + consumed < size &&
             data[i + consumed] >= 0x80 && data[i + consumed] <= 0xbf) {
        consumed += 1;
      }
    }
    if (consumed == expected) {
      for (size_t k = 0; k < expected; k++) {
        out.push_back(data[i + k]);
      }
    } else {
      if (fatal) {
        throwTypeError(rt, intrinsics, "TextDecoder: input is not valid UTF-8");
      }
      out.push_back(0xef);
      out.push_back(0xbf);
      out.push_back(0xbd);
    }
    i += consumed;
  }
  return out;
}

jsi::ArrayBuffer arrayBufferFromBytes(
    jsi::Runtime& rt,
    const uint8_t* bytes,
    size_t size) {
  auto buffer = std::make_shared<OwningBuffer>(size);
  if (bytes != nullptr && size > 0) {
    std::memcpy(buffer->data(), bytes, size);
  }
  return rt.createArrayBuffer(std::move(buffer));
}

jsi::Object makeUint8Array(
    jsi::Runtime& rt,
    const KernelIntrinsics& intrinsics,
    jsi::ArrayBuffer buffer) {
  return intrinsics.uint8Array
      .callAsConstructor(rt, jsi::Value(std::move(buffer)))
      .asObject(rt);
}

std::shared_ptr<KernelIntrinsics> captureIntrinsics(jsi::Runtime& rt) {
  auto global = rt.global();
  auto objectCtor = global.getPropertyAsObject(rt, "Object");
  auto getPrototypeOf = objectCtor.getPropertyAsFunction(rt, "getPrototypeOf");
  auto getDescriptor = objectCtor.getPropertyAsFunction(rt, "getOwnPropertyDescriptor");

  auto requireGetter = [&](const char* name,
                           const jsi::Value& container,
                           const jsi::Value& key) -> jsi::Function {
    const jsi::Value descriptor = getDescriptor.call(rt, container, key);
    const jsi::Value get = descriptor.isObject()
        ? descriptor.asObject(rt).getProperty(rt, "get")
        : jsi::Value::undefined();
    if (!get.isObject() || !get.asObject(rt).isFunction(rt)) {
      throw std::runtime_error(
          std::string("kernel globals: missing TypedArray intrinsic ") + name);
    }
    return get.asObject(rt).asFunction(rt);
  };

  auto uint8Array = global.getPropertyAsFunction(rt, "Uint8Array");
  const jsi::Value typedArrayProto =
      getPrototypeOf.call(rt, uint8Array.getProperty(rt, "prototype"));
  const jsi::Value toStringTag =
      global.getPropertyAsObject(rt, "Symbol").getProperty(rt, "toStringTag");
  const auto nameKey = [&](const char* name) {
    return jsi::Value(rt, jsi::String::createFromAscii(rt, name));
  };

  return std::shared_ptr<KernelIntrinsics>(new KernelIntrinsics{
      objectCtor.getPropertyAsFunction(rt, "defineProperty"),
      objectCtor.getPropertyAsFunction(rt, "freeze"),
      global.getPropertyAsFunction(rt, "TypeError"),
      std::move(uint8Array),
      requireGetter("buffer", typedArrayProto, nameKey("buffer")),
      requireGetter("byteOffset", typedArrayProto, nameKey("byteOffset")),
      requireGetter("byteLength", typedArrayProto, nameKey("byteLength")),
      requireGetter("Symbol.toStringTag", typedArrayProto, toStringTag),
  });
}

void defineHiddenGlobal(
    jsi::Runtime& rt,
    const KernelIntrinsics& intrinsics,
    const char* name,
    jsi::Value value) {
  jsi::Object descriptor(rt);
  descriptor.setProperty(rt, "value", std::move(value));
  descriptor.setProperty(rt, "writable", jsi::Value(false));
  descriptor.setProperty(rt, "configurable", jsi::Value(false));
  descriptor.setProperty(rt, "enumerable", jsi::Value(false));
  intrinsics.defineProperty.call(
      rt,
      rt.global(),
      jsi::Value(rt, jsi::String::createFromAscii(rt, name)),
      jsi::Value(std::move(descriptor)));
}

// One process-wide worker runs every PBKDF2 job, so concurrent kernels cannot
// spawn unbounded derivation threads. The queue is bounded; the worker thread
// is intentionally leaked rather than joined (it parks on the condition
// variable and holds no runtime state).
struct KdfJob {
  KernelPbkdf2Hash hash;
  SecretBytes password;
  SecretBytes salt;
  uint32_t iterations;
  size_t length;
  std::shared_ptr<KernelPendingCall> call;
  std::shared_ptr<KernelGlobalsState> state;
};

struct KdfQueue {
  std::mutex mutex;
  std::condition_variable cv;
  std::deque<KdfJob> jobs;
  bool workerStarted = false;
};

KdfQueue& kdfQueue() {
  static auto* queue = new KdfQueue();
  return *queue;
}

void kdfWorkerRun() {
  auto& queue = kdfQueue();
  for (;;) {
    KdfJob job;
    {
      std::unique_lock<std::mutex> lock(queue.mutex);
      queue.cv.wait(lock, [&] { return !queue.jobs.empty(); });
      job = std::move(queue.jobs.front());
      queue.jobs.pop_front();
    }
    if (!job.state->active->load(std::memory_order_acquire)) {
      continue;
    }
    SecretBytes derived;
    std::string error;
    try {
      derived = kernelPbkdf2(
          job.hash, job.password, job.salt, job.iterations, job.length);
    } catch (const std::exception& e) {
      error = e.what();
    } catch (...) {
      error = "unknown pbkdf2 error";
    }
    if (!job.state->active->load(std::memory_order_acquire)) {
      // Runtime torn down mid-derivation: drop the job; the parked call's
      // `done` was already cleared by teardown, and SecretBytes wipe here.
      continue;
    }
    auto state = job.state;
    auto call = job.call;
    // std::function needs a copyable closure: share the result; whichever
    // side drops it last wipes it.
    auto result = std::make_shared<SecretBytes>(std::move(derived));
    state->enqueueTask(
        [state, call, result, error = std::move(error)](
            jsi::Runtime& rt) mutable {
          auto done = std::move(call->done);
          state->pending.erase(call);
          if (!done.has_value()) {
            return;
          }
          if (!error.empty()) {
            done->call(
                rt,
                jsi::Value::undefined(),
                jsi::Value(rt, jsi::String::createFromUtf8(rt, error)));
            return;
          }
          auto buffer =
              arrayBufferFromBytes(rt, result->data(), result->size());
          auto array = makeUint8Array(rt, *state->intrinsics, std::move(buffer));
          done->call(rt, jsi::Value(std::move(array)), jsi::Value::undefined());
        });
  }
}

void kdfWorkerMain() {
#if defined(__APPLE__)
  pthread_setname_np("qntx-kdf");
#elif defined(__ANDROID__)
  pthread_setname_np(pthread_self(), "qntx-kdf");
#endif
  auto body = [] { kdfWorkerRun(); };
#if defined(__ANDROID__)
  // The worker calls into javax.crypto over JNI; attach it to the JVM once for
  // its lifetime (and let the app class loader resolve KernelPbkdf2).
  facebook::jni::ThreadScope::WithClassLoader(std::move(body));
#else
  body();
#endif
}

bool kdfSubmit(KdfJob job) {
  auto& queue = kdfQueue();
  std::lock_guard<std::mutex> lock(queue.mutex);
  if (queue.jobs.size() >= kKdfQueueLimit) {
    return false;
  }
  queue.jobs.push_back(std::move(job));
  if (!queue.workerStarted) {
    queue.workerStarted = true;
    std::thread(kdfWorkerMain).detach();
  }
  queue.cv.notify_one();
  return true;
}

void installPbkdf2(
    jsi::Runtime& rt,
    jsi::Object& qntx,
    const std::shared_ptr<KernelGlobalsState>& state) {
  qntx.setProperty(
      rt,
      "pbkdf2",
      hostFn(rt, "pbkdf2", 6, [state](jsi::Runtime& rt, const jsi::Value&, const jsi::Value* args, size_t count) -> jsi::Value {
        if (count < 6) {
          throw jsi::JSError(
              rt, "__qntx.pbkdf2 expects (hash, password, salt, iterations, length, done)");
        }
        const auto& intrinsics = *state->intrinsics;
        if (!args[0].isString()) {
          throw jsi::JSError(
              rt, "__qntx.pbkdf2 expects (hash, password, salt, iterations, length, done)");
        }
        const auto hashName = args[0].asString(rt).utf8(rt);
        KernelPbkdf2Hash hash;
        if (hashName == "sha256") {
          hash = KernelPbkdf2Hash::sha256;
        } else if (hashName == "sha512") {
          hash = KernelPbkdf2Hash::sha512;
        } else {
          throw jsi::JSError(rt, "__qntx.pbkdf2 hash must be sha256 or sha512");
        }
        auto passwordView =
            byteViewFromValue(rt, args[1], "__qntx.pbkdf2 password", intrinsics);
        SecretBytes password(passwordView.data, passwordView.size);
        auto saltView =
            byteViewFromValue(rt, args[2], "__qntx.pbkdf2 salt", intrinsics);
        SecretBytes salt(saltView.data, saltView.size);
        if (!args[5].isObject() || !args[5].asObject(rt).isFunction(rt)) {
          throw jsi::JSError(
              rt, "__qntx.pbkdf2 expects (hash, password, salt, iterations, length, done)");
        }
        const auto iterations = static_cast<uint32_t>(
            integerInRange(rt, args[3], "__qntx.pbkdf2 iterations", 1, kPbkdf2IterationsMax));
        const auto length = static_cast<size_t>(
            integerInRange(rt, args[4], "__qntx.pbkdf2 length", 1, kPbkdf2LengthMax));
        auto call = std::make_shared<KernelPendingCall>();
        call->done = args[5].asObject(rt).asFunction(rt);
        state->pending.insert(call);

        KdfJob job{
            hash,
            std::move(password),
            std::move(salt),
            iterations,
            length,
            call,
            state};
        if (!kdfSubmit(std::move(job))) {
          state->enqueueTask([state, call](jsi::Runtime& rt) mutable {
            auto done = std::move(call->done);
            state->pending.erase(call);
            if (done.has_value()) {
              done->call(
                  rt,
                  jsi::Value::undefined(),
                  jsi::Value(rt, jsi::String::createFromAscii(rt, "kdf queue full")));
            }
          });
        }
        return jsi::Value::undefined();
      }));
}

// Runs once before the kernel script: defines TextDecoder, installs the
// setTimeout/clearTimeout globals Hermes' bundled rejection tracker defers
// through, and wires that tracker to the private reportUnhandled native. The
// expression evaluates to the function object; C++ invokes it with `natives`.
const char kKernelPrelude[] = R"JS((function (natives) {
  var defineHidden = function (name, value) {
    Object.defineProperty(globalThis, name, {
      value: value,
      writable: false,
      configurable: false,
      enumerable: false,
    });
  };

  function TextDecoder(label, options) {
    var encoding = label === undefined ? "utf-8" : String(label);
    encoding = encoding.replace(/^\s+|\s+$/g, "").toLowerCase();
    if (
      encoding !== "utf-8" &&
      encoding !== "utf8" &&
      encoding !== "unicode-1-1-utf-8"
    ) {
      throw new RangeError("TextDecoder: unsupported label " + encoding);
    }
    options = options == null ? {} : options;
    this.encoding = "utf-8";
    this.fatal = options.fatal === true;
    this.ignoreBOM = options.ignoreBOM === true;
  }
  TextDecoder.prototype.decode = function (input, options) {
    if (input === undefined) {
      return "";
    }
    if (options != null && options.stream === true) {
      throw new TypeError("TextDecoder: stream is not supported");
    }
    return natives.decodeUtf8(input, this.fatal, this.ignoreBOM);
  };
  defineHidden("TextDecoder", TextDecoder);
  // The prelude runs before any script, so these intrinsics are still
  // pristine; a tampered prototype must not be able to replace decode.
  Object.freeze(TextDecoder.prototype);
  Object.freeze(TextDecoder);

  // Hermes' bundled rejection tracker defers onUnhandled through the literal
  // globals setTimeout/clearTimeout resolved at call time — Promise.then and
  // async/await use the engine queue instead and need nothing. These are the
  // only two timer globals the runtime installs (measured: without them
  // onUnhandled never fires).
  var timerSeq = 0;
  var timerCancels = {};
  defineHidden("setTimeout", function (fn, ms) {
    var id = ++timerSeq;
    var cancel = natives.setTimer(ms === undefined ? 0 : ms, function () {
      delete timerCancels[id];
      fn();
    });
    timerCancels[id] = cancel;
    return id;
  });
  defineHidden("clearTimeout", function (id) {
    var cancel = timerCancels[id];
    if (cancel !== undefined) {
      delete timerCancels[id];
      cancel();
    }
  });

  if (
    typeof HermesInternal === "object" &&
    HermesInternal !== null &&
    typeof HermesInternal.enablePromiseRejectionTracker === "function"
  ) {
    HermesInternal.enablePromiseRejectionTracker({
      allRejections: true,
      onHandled: function () {},
      onUnhandled: function (id, reason) {
        natives.reportUnhandled(
          id,
          reason == null
            ? "unknown"
            : String(reason && reason.stack ? reason.stack : reason));
      },
    });
  }
}))JS";

} // namespace

void installKernelGlobals(
    jsi::Runtime& rt,
    const std::shared_ptr<KernelGlobalsState>& state) {
  auto intrinsics = captureIntrinsics(rt);
  state->intrinsics = intrinsics;

  auto global = rt.global();
  auto qntx = jsi::Object(rt);

  qntx.setProperty(
      rt,
      "random",
      hostFn(rt, "random", 1, [state](jsi::Runtime& rt, const jsi::Value&, const jsi::Value* args, size_t count) -> jsi::Value {
        if (count < 1) {
          throw jsi::JSError(rt, "__qntx.random expects a byte length");
        }
        const auto n = static_cast<size_t>(
            integerInRange(rt, args[0], "__qntx.random length", 0, kRandomLimit));
        auto buffer = arrayBufferFromBytes(rt, nullptr, n);
        fillRandom(buffer.data(rt), buffer.size(rt));
        return jsi::Value(rt, makeUint8Array(rt, *state->intrinsics, std::move(buffer)));
      }));

  qntx.setProperty(
      rt,
      "now",
      hostFn(rt, "now", 0, [](jsi::Runtime&, const jsi::Value&, const jsi::Value*, size_t) -> jsi::Value {
        // Whole milliseconds like Date.now(): vault headers require integer
        // createdAt timestamps.
        return jsi::Value(static_cast<double>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count()));
      }));

  qntx.setProperty(
      rt,
      "elapsed",
      hostFn(rt, "elapsed", 0, [](jsi::Runtime&, const jsi::Value&, const jsi::Value*, size_t) -> jsi::Value {
        return jsi::Value(std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count());
      }));

  const auto makeSetTimer = [&state](jsi::Runtime& rt) -> jsi::Function {
    return hostFn(rt, "setTimer", 2, [state](jsi::Runtime& rt, const jsi::Value&, const jsi::Value* args, size_t count) -> jsi::Value {
      if (count < 2 || !args[1].isObject() || !args[1].asObject(rt).isFunction(rt)) {
        throw jsi::JSError(rt, "__qntx.setTimer expects (delayMs, fn)");
      }
      const double delayMs = finiteNumber(rt, args[0], "__qntx.setTimer delay");
      if (delayMs < 0 || delayMs > kTimerDelayMax) {
        throw jsi::JSError(rt, "__qntx.setTimer delay out of range");
      }
      const auto deadline = std::chrono::steady_clock::now() +
          std::chrono::milliseconds(static_cast<int64_t>(std::ceil(delayMs)));
      auto cancel = state->scheduleTimer(deadline, args[1].asObject(rt).asFunction(rt));
      return jsi::Value(rt, hostFn(rt, "cancel", 0, [cancel = std::move(cancel)](jsi::Runtime&, const jsi::Value&, const jsi::Value*, size_t) mutable -> jsi::Value {
        cancel();
        return jsi::Value::undefined();
      }));
    });
  };
  qntx.setProperty(rt, "setTimer", makeSetTimer(rt));

  installPbkdf2(rt, qntx, state);

  qntx.setProperty(
      rt,
      "post",
      hostFn(rt, "post", 1, [state](jsi::Runtime& rt, const jsi::Value&, const jsi::Value* args, size_t count) -> jsi::Value {
        if (count < 1 || !args[0].isObject() || !args[0].asObject(rt).isArrayBuffer(rt)) {
          throw jsi::JSError(rt, "__qntx.post expects an ArrayBuffer");
        }
        auto buffer = args[0].asObject(rt).getArrayBuffer(rt);
        const auto* data = buffer.data(rt);
        state->postToHost(std::vector<uint8_t>(data, data + buffer.size(rt)));
        return jsi::Value::undefined();
      }));

  qntx.setProperty(
      rt,
      "setMessageHandler",
      hostFn(rt, "setMessageHandler", 1, [state](jsi::Runtime& rt, const jsi::Value&, const jsi::Value* args, size_t count) -> jsi::Value {
        if (count < 1 || !args[0].isObject() || !args[0].asObject(rt).isFunction(rt)) {
          throw jsi::JSError(rt, "__qntx.setMessageHandler expects a function");
        }
        state->messageHandler = args[0].asObject(rt).asFunction(rt);
        return jsi::Value::undefined();
      }));

  intrinsics->freeze.call(rt, jsi::Value(rt, qntx));
  defineHiddenGlobal(rt, *intrinsics, "__qntx", jsi::Value(std::move(qntx)));

  auto cryptoObject = jsi::Object(rt);
  cryptoObject.setProperty(
      rt,
      "getRandomValues",
      hostFn(rt, "getRandomValues", 1, [state](jsi::Runtime& rt, const jsi::Value&, const jsi::Value* args, size_t count) -> jsi::Value {
        if (count < 1 || !args[0].isObject()) {
          throw jsi::JSError(rt, "crypto.getRandomValues expects a TypedArray");
        }
        const auto& intrinsics = *state->intrinsics;
        auto view = args[0].asObject(rt);
        const jsi::Value tag = intrinsics.taTagGet.callWithThis(rt, view);
        static const char* const kIntegerArrays[] = {
            "Int8Array",
            "Uint8Array",
            "Uint8ClampedArray",
            "Int16Array",
            "Uint16Array",
            "Int32Array",
            "Uint32Array",
            "BigInt64Array",
            "BigUint64Array",
        };
        const std::string tagName =
            tag.isString() ? tag.asString(rt).utf8(rt) : std::string();
        bool integerTyped = false;
        for (const char* allowed : kIntegerArrays) {
          if (tagName == allowed) {
            integerTyped = true;
            break;
          }
        }
        if (!integerTyped) {
          throw jsi::JSError(
              rt, "crypto.getRandomValues accepts only integer TypedArrays");
        }
        auto bytes =
            byteViewFromValue(rt, args[0], "crypto.getRandomValues", intrinsics);
        if (bytes.size > kRandomLimit) {
          throw jsi::JSError(
              rt, "QuotaExceededError: crypto.getRandomValues view exceeds 65536 bytes");
        }
        fillRandom(bytes.data, bytes.size);
        return jsi::Value(rt, args[0]);
      }));
  intrinsics->freeze.call(rt, jsi::Value(rt, cryptoObject));
  defineHiddenGlobal(
      rt, *intrinsics, "crypto", jsi::Value(std::move(cryptoObject)));

  auto natives = jsi::Object(rt);
  natives.setProperty(rt, "setTimer", makeSetTimer(rt));
  natives.setProperty(
      rt,
      "decodeUtf8",
      hostFn(rt, "decodeUtf8", 3, [state](jsi::Runtime& rt, const jsi::Value&, const jsi::Value* args, size_t count) -> jsi::Value {
        if (count < 3 || !args[1].isBool() || !args[2].isBool()) {
          throw jsi::JSError(rt, "decodeUtf8 expects (bytes, fatal, ignoreBOM)");
        }
        const auto& intrinsics = *state->intrinsics;
        auto view = byteViewFromValue(rt, args[0], "decodeUtf8 input", intrinsics);
        auto decoded = decodeUtf8Bytes(
            rt, intrinsics, view.data, view.size, args[1].getBool(), args[2].getBool());
        return jsi::Value(
            rt, jsi::String::createFromUtf8(rt, decoded.data(), decoded.size()));
      }));
  natives.setProperty(
      rt,
      "reportUnhandled",
      hostFn(rt, "reportUnhandled", 2, [state](jsi::Runtime& rt, const jsi::Value&, const jsi::Value* args, size_t count) -> jsi::Value {
        std::string reason = "unhandled promise rejection";
        if (count > 0 && args[0].isNumber()) {
          reason += " id=" +
              std::to_string(static_cast<long long>(args[0].getNumber()));
        }
        if (count > 1 && args[1].isString()) {
          reason += ": " + args[1].asString(rt).utf8(rt);
        }
        state->reportFatal(std::move(reason));
        return jsi::Value::undefined();
      }));

  auto prelude = rt.evaluateJavaScript(
      std::make_shared<jsi::StringBuffer>(kKernelPrelude), "<kernel-prelude>");
  prelude.asObject(rt).asFunction(rt).call(rt, jsi::Value(std::move(natives)));
}

} // namespace qntx
