#pragma once

#include <cstdint>
#include <vector>

#ifdef __ANDROID__
#include <jni.h>
#endif

namespace qntx {

enum class KernelPbkdf2Hash { sha256, sha512 };

// Synchronous PBKDF2: iOS/macOS via CommonCrypto, Android via JNI into
// javax.crypto. Callers run it on a background thread — never on the kernel
// thread. Throws std::runtime_error on failure. Inputs are not wiped here;
// the caller owns wiping.
std::vector<uint8_t> kernelPbkdf2(
    KernelPbkdf2Hash hash,
    const std::vector<uint8_t>& password,
    const std::vector<uint8_t>& salt,
    uint32_t iterations,
    size_t length);

// Zeroes secret bytes without letting the optimizer elide the store.
void kernelWipe(uint8_t* data, size_t size);
void kernelWipe(std::vector<uint8_t>& bytes);

#ifdef __ANDROID__
// Called from the module's JNI_OnLoad while the caller's classloader is
// available; caches the JavaVM and the Java helper's class/method.
void kernelPbkdf2OnLoad(JNIEnv* env, const char* className);

// The cached JavaVM, or nullptr before kernelPbkdf2OnLoad runs. The kernel
// thread attaches through this when a probe installs JNI-backed natives
// (e.g. Nitro's Java-bridged HybridObjectRegistry on Android).
JavaVM* kernelJavaVM();
#endif

} // namespace qntx
