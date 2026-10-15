#include "KernelPbkdf2.hpp"

#include <stdexcept>
#include <string>

#if defined(__APPLE__)
#include <CommonCrypto/CommonCryptoError.h>
#include <CommonCrypto/CommonKeyDerivation.h>
#endif

void qntx::kernelWipe(uint8_t* data, size_t size) {
  volatile uint8_t* p = data;
  for (size_t i = 0; i < size; i++) {
    p[i] = 0;
  }
}

void qntx::kernelWipe(std::vector<uint8_t>& bytes) {
  kernelWipe(bytes.data(), bytes.size());
}

#if defined(__APPLE__)

std::vector<uint8_t> qntx::kernelPbkdf2(
    KernelPbkdf2Hash hash,
    const std::vector<uint8_t>& password,
    const std::vector<uint8_t>& salt,
    uint32_t iterations,
    size_t length) {
  const CCPseudoRandomAlgorithm algorithm =
      hash == KernelPbkdf2Hash::sha256 ? kCCPRFHmacAlgSHA256 : kCCPRFHmacAlgSHA512;
  std::vector<uint8_t> out(length);
  const int status = CCKeyDerivationPBKDF(
      kCCPBKDF2,
      reinterpret_cast<const char*>(password.data()),
      password.size(),
      salt.data(),
      salt.size(),
      algorithm,
      iterations,
      out.data(),
      out.size());
  if (status != kCCSuccess) {
    throw std::runtime_error("CCKeyDerivationPBKDF failed: " + std::to_string(status));
  }
  return out;
}

#elif defined(__ANDROID__)

namespace {

JavaVM* g_vm = nullptr;
jclass g_class = nullptr;
jmethodID g_derive = nullptr;

// Attaches the current thread to the JVM for the scope's lifetime.
struct JniScope {
  JNIEnv* env = nullptr;
  bool mustDetach = false;

  JniScope() {
    if (g_vm == nullptr) {
      throw std::runtime_error("kernelPbkdf2OnLoad was not called");
    }
    if (g_vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) == JNI_EDETACHED) {
      if (g_vm->AttachCurrentThread(&env, nullptr) != JNI_OK) {
        throw std::runtime_error("AttachCurrentThread failed");
      }
      mustDetach = true;
    }
  }
  ~JniScope() {
    if (mustDetach) {
      g_vm->DetachCurrentThread();
    }
  }
  JniScope(const JniScope&) = delete;
  JniScope& operator=(const JniScope&) = delete;
};

class JniByteArray {
 public:
  JniByteArray(JNIEnv* env, const std::vector<uint8_t>& bytes) : env_(env) {
    array_ = env->NewByteArray(static_cast<jsize>(bytes.size()));
    if (array_ == nullptr) {
      throw std::runtime_error("NewByteArray failed");
    }
    if (!bytes.empty()) {
      env->SetByteArrayRegion(
          array_, 0, static_cast<jsize>(bytes.size()),
          reinterpret_cast<const jbyte*>(bytes.data()));
    }
  }
  ~JniByteArray() {
    if (array_ != nullptr) {
      // Wipe the heap copy before releasing the local ref.
      std::vector<jbyte> zeros(env_->GetArrayLength(array_), 0);
      env_->SetByteArrayRegion(array_, 0, static_cast<jsize>(zeros.size()), zeros.data());
      env_->DeleteLocalRef(array_);
    }
  }
  JniByteArray(const JniByteArray&) = delete;
  JniByteArray& operator=(const JniByteArray&) = delete;
  jbyteArray get() const {
    return array_;
  }

 private:
  JNIEnv* env_;
  jbyteArray array_ = nullptr;
};

std::string describeJavaException(JNIEnv* env) {
  if (!env->ExceptionCheck()) {
    return {};
  }
  jthrowable throwable = env->ExceptionOccurred();
  env->ExceptionClear();
  auto objectClass = env->GetObjectClass(throwable);
  auto toStringId = env->GetMethodID(objectClass, "toString", "()Ljava/lang/String;");
  auto message = static_cast<jstring>(
      env->CallObjectMethod(throwable, toStringId));
  std::string text = "java exception";
  if (message != nullptr) {
    const char* utf = env->GetStringUTFChars(message, nullptr);
    if (utf != nullptr) {
      text = utf;
      env->ReleaseStringUTFChars(message, utf);
    }
    env->DeleteLocalRef(message);
  }
  env->DeleteLocalRef(objectClass);
  env->DeleteLocalRef(throwable);
  return text;
}

} // namespace

JavaVM* qntx::kernelJavaVM() {
  return g_vm;
}

void qntx::kernelPbkdf2OnLoad(JNIEnv* env, const char* className) {
  if (env->GetJavaVM(&g_vm) != JNI_OK) {
    throw std::runtime_error("GetJavaVM failed");
  }
  jclass local = env->FindClass(className);
  if (local == nullptr) {
    env->ExceptionClear();
    throw std::runtime_error(std::string("pbkdf2 helper class not found: ") + className);
  }
  g_class = static_cast<jclass>(env->NewGlobalRef(local));
  env->DeleteLocalRef(local);
  g_derive = env->GetStaticMethodID(
      g_class, "derive", "(Ljava/lang/String;[B[BII)[B");
  if (g_derive == nullptr) {
    env->ExceptionClear();
    throw std::runtime_error("KernelPbkdf2.derive not found");
  }
}

std::vector<uint8_t> qntx::kernelPbkdf2(
    KernelPbkdf2Hash hash,
    const std::vector<uint8_t>& password,
    const std::vector<uint8_t>& salt,
    uint32_t iterations,
    size_t length) {
  JniScope scope;
  JNIEnv* env = scope.env;

  jstring algorithm = env->NewStringUTF(
      hash == KernelPbkdf2Hash::sha256 ? "PBKDF2WithHmacSHA256" : "PBKDF2WithHmacSHA512");
  JniByteArray passwordArray(env, password);
  JniByteArray saltArray(env, salt);

  auto result = static_cast<jbyteArray>(env->CallStaticObjectMethod(
      g_class,
      g_derive,
      algorithm,
      passwordArray.get(),
      saltArray.get(),
      static_cast<jint>(iterations),
      static_cast<jint>(length)));
  env->DeleteLocalRef(algorithm);
  if (result == nullptr) {
    throw std::runtime_error("pbkdf2 failed: " + describeJavaException(env));
  }
  const jsize size = env->GetArrayLength(result);
  std::vector<uint8_t> out(static_cast<size_t>(size));
  env->GetByteArrayRegion(result, 0, size, reinterpret_cast<jbyte*>(out.data()));
  std::vector<jbyte> zeros(size, 0);
  env->SetByteArrayRegion(result, 0, size, zeros.data());
  env->DeleteLocalRef(result);
  return out;
}

#else

std::vector<uint8_t> qntx::kernelPbkdf2(
    KernelPbkdf2Hash,
    const std::vector<uint8_t>&,
    const std::vector<uint8_t>&,
    uint32_t,
    size_t) {
  throw std::runtime_error("kernelPbkdf2: unsupported platform");
}

#endif
