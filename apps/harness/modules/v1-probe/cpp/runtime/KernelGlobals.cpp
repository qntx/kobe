#include "KernelGlobals.hpp"

#include "KernelBuffer.hpp"
#include "platform/KernelPbkdf2.hpp"

#include <cstdlib>
#include <thread>

#if defined(__APPLE__) || defined(__ANDROID__)
#include <unistd.h>
#endif

namespace qntx {

namespace {

jsi::ArrayBuffer arrayBufferFromBytes(jsi::Runtime& rt, const uint8_t* bytes, size_t size) {
  auto buffer = std::make_shared<OwningBuffer>(size);
  if (bytes != nullptr && size > 0) {
    std::memcpy(buffer->data(), bytes, size);
  }
  return rt.createArrayBuffer(std::move(buffer));
}

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
#else
  for (size_t i = 0; i < size; i++) {
    out[i] = static_cast<uint8_t>(std::rand());
  }
#endif
}

jsi::Object makeUint8Array(jsi::Runtime& rt, jsi::ArrayBuffer&& buffer) {
  auto global = rt.global();
  auto ctor = global.getPropertyAsFunction(rt, "Uint8Array");
  return ctor.callAsConstructor(rt, jsi::Value(std::move(buffer))).asObject(rt);
}

// Copies the bytes out of an ArrayBuffer or a TypedArray view of one.
std::vector<uint8_t> bytesFromValue(jsi::Runtime& rt, const jsi::Value& value, const char* name) {
  if (!value.isObject()) {
    throw jsi::JSError(rt, std::string(name) + " expects an ArrayBuffer or Uint8Array");
  }
  auto object = value.asObject(rt);
  if (object.isArrayBuffer(rt)) {
    auto buffer = object.getArrayBuffer(rt);
    const auto* data = buffer.data(rt);
    return {data, data + buffer.size(rt)};
  }
  const auto buffer = object.getPropertyAsObject(rt, "buffer").getArrayBuffer(rt);
  const auto offset =
      static_cast<size_t>(object.getProperty(rt, "byteOffset").asNumber());
  const auto size =
      static_cast<size_t>(object.getProperty(rt, "byteLength").asNumber());
  const auto* data = buffer.data(rt);
  return {data + offset, data + offset + size};
}

} // namespace

void installKernelGlobals(
    jsi::Runtime& rt,
    const std::shared_ptr<KernelGlobalsState>& state) {
  auto global = rt.global();
  auto qntx = jsi::Object(rt);

  qntx.setProperty(
      rt,
      "random",
      hostFn(rt, "random", 1, [state](jsi::Runtime& rt, const jsi::Value&, const jsi::Value* args, size_t count) -> jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          throw jsi::JSError(rt, "__qntx.random expects a byte length");
        }
        const auto n = args[0].getNumber();
        if (n < 0 || n > 1 << 22) {
          throw jsi::JSError(rt, "__qntx.random length out of range");
        }
        auto buffer = arrayBufferFromBytes(rt, nullptr, static_cast<size_t>(n));
        fillRandom(buffer.data(rt), buffer.size(rt));
        return jsi::Value(rt, makeUint8Array(rt, std::move(buffer)));
      }));

  qntx.setProperty(
      rt,
      "now",
      hostFn(rt, "now", 0, [](jsi::Runtime&, const jsi::Value&, const jsi::Value*, size_t) -> jsi::Value {
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count();
        return jsi::Value(static_cast<double>(ms));
      }));

  qntx.setProperty(
      rt,
      "setTimer",
      hostFn(rt, "setTimer", 2, [state](jsi::Runtime& rt, const jsi::Value&, const jsi::Value* args, size_t count) -> jsi::Value {
        if (count < 2 || !args[0].isNumber() || !args[1].isObject() ||
            !args[1].asObject(rt).isFunction(rt)) {
          throw jsi::JSError(rt, "__qntx.setTimer expects (delayMs, fn)");
        }
        const double delayMs = args[0].getNumber();
        auto deadline =
            std::chrono::steady_clock::now() +
            std::chrono::milliseconds(static_cast<int64_t>(delayMs < 0 ? 0 : delayMs));
        auto cancel = state->scheduleTimer(deadline, args[1].asObject(rt).asFunction(rt));
        return jsi::Value(rt, hostFn(rt, "cancel", 0, [cancel](jsi::Runtime&, const jsi::Value&, const jsi::Value*, size_t) -> jsi::Value {
          cancel->store(true, std::memory_order_relaxed);
          return jsi::Value::undefined();
        }));
      }));

  qntx.setProperty(
      rt,
      "pbkdf2",
      hostFn(rt, "pbkdf2", 6, [state](jsi::Runtime& rt, const jsi::Value&, const jsi::Value* args, size_t count) -> jsi::Value {
        if (count < 6 || !args[0].isString()) {
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
        auto password = bytesFromValue(rt, args[1], "__qntx.pbkdf2 password");
        auto salt = bytesFromValue(rt, args[2], "__qntx.pbkdf2 salt");
        if (!args[3].isNumber() || !args[4].isNumber() || !args[5].isObject() ||
            !args[5].asObject(rt).isFunction(rt)) {
          kernelWipe(password);
          throw jsi::JSError(rt, "__qntx.pbkdf2 expects (hash, password, salt, iterations, length, done)");
        }
        const auto iterations = args[3].asNumber();
        const auto length = args[4].asNumber();
        if (iterations < 1 || iterations > 1'000'000'000 || length < 1 || length > 1 << 20) {
          kernelWipe(password);
          throw jsi::JSError(rt, "__qntx.pbkdf2 iterations/length out of range");
        }
        auto call = std::make_shared<KernelPendingCall>();
        call->done = args[5].asObject(rt).asFunction(rt);
        state->pending.insert(call);

        const auto iterationCount = static_cast<uint32_t>(iterations);
        const auto derivedLength = static_cast<size_t>(length);
        std::thread(
            [state, call, hash, password = std::move(password), salt = std::move(salt),
             iterationCount, derivedLength]() mutable {
              std::vector<uint8_t> derived;
              std::string error;
              try {
                derived = kernelPbkdf2(hash, password, salt, iterationCount, derivedLength);
              } catch (const std::exception& e) {
                error = e.what();
              } catch (...) {
                error = "unknown pbkdf2 error";
              }
              kernelWipe(password);
              kernelWipe(salt);
              state->enqueueTask(
                  [state, call, derived = std::move(derived), error = std::move(error)](
                      jsi::Runtime& rt) mutable {
                    auto done = std::move(call->done);
                    state->pending.erase(call);
                    if (!done.has_value()) {
                      kernelWipe(derived);
                      return;
                    }
                    if (!error.empty()) {
                      kernelWipe(derived);
                      done->call(
                          rt,
                          jsi::Value::undefined(),
                          jsi::Value(rt, jsi::String::createFromUtf8(rt, error)));
                      return;
                    }
                    auto buffer =
                        arrayBufferFromBytes(rt, derived.data(), derived.size());
                    kernelWipe(derived);
                    auto array = makeUint8Array(rt, std::move(buffer));
                    done->call(rt, jsi::Value(rt, array), jsi::Value::undefined());
                  });
            })
            .detach();
        return jsi::Value::undefined();
      }));

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

  global.setProperty(rt, "__qntxUnhandledRejection", hostFn(rt, "__qntxUnhandledRejection", 2, [state](jsi::Runtime& rt, const jsi::Value&, const jsi::Value* args, size_t count) -> jsi::Value {
    std::string reason = "unhandled promise rejection";
    if (count > 0 && args[0].isNumber()) {
      reason += " id=" + std::to_string(static_cast<long long>(args[0].getNumber()));
    }
    if (count > 1 && args[1].isString()) {
      reason += ": " + args[1].asString(rt).utf8(rt);
    }
    state->reportFatal(std::move(reason));
    return jsi::Value::undefined();
  }));

  global
      .getPropertyAsObject(rt, "Object")
      .getPropertyAsFunction(rt, "freeze")
      .call(rt, jsi::Value(rt, qntx));
  global.setProperty(rt, "__qntx", std::move(qntx));
}

} // namespace qntx
