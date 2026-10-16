#pragma once

#include "../KernelBuffer.hpp"

#include <cstdint>
#include <vector>

#ifdef __ANDROID__
#include <jni.h>
#endif

namespace qntx {

enum class KernelPbkdf2Hash { sha256, sha512 };

// Synchronous PBKDF2: iOS/macOS via CommonCrypto, Android via JNI into
// javax.crypto.Mac. Callers run it on the KDF worker thread — never on the
// kernel thread. Throws std::runtime_error on failure. Inputs and the result
// are SecretBytes, so any path that drops them still wipes them.
SecretBytes kernelPbkdf2(
    KernelPbkdf2Hash hash,
    const SecretBytes& password,
    const SecretBytes& salt,
    uint32_t iterations,
    size_t length);

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
