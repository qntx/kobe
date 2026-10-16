#include "V1ProbeOnLoad.hpp"
#include "runtime/platform/KernelPbkdf2.hpp"
#include <fbjni/fbjni.h>
#include <jni.h>

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
  return facebook::jni::initialize(vm, []() {
    margelo::nitro::v1probe::registerAllNatives();
    qntx::kernelPbkdf2OnLoad(
        facebook::jni::Environment::current(),
        "com/margelo/nitro/v1probe/KernelPbkdf2");
  });
}
