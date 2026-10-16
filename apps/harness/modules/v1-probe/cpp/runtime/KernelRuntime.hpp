#pragma once

#include <hermes/hermes.h>
#include <jsi/jsi.h>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace qntx {

// Hermes hardening level for the kernel runtime. `standard` runs a plain
// HermesVM config; `hardened` starts from hermes' hardenedHermesRuntimeConfig()
// (untrusted-code profile). Both disable eval, enable the runtime-owned
// microtask queue, and emit async break checks in eval-compiled code.
enum class KernelProfile { standard, hardened };

// Immutable script payload: bundled kernel source or compiled Hermes bytecode.
// Bytecode must be built with hermesc -emit-async-break-check so destroy() can
// interrupt running JS.
struct KernelScript {
  enum class Kind { source, bytecode };
  Kind kind;
  std::shared_ptr<const std::vector<uint8_t>> bytes;
};

// A Hermes runtime running the wallet kernel on its own thread, driven by a
// task queue instead of the JS event loop.
//
// Lifecycle:
//   - start() returns a shared_ptr; the kernel thread is detached and owns the
//     shared state, so dropping the last KernelRuntime does not leak or hang.
//   - destroy() requests shutdown: it is noexcept, idempotent, callable from
//     any thread (including the kernel thread itself), and never blocks — it
//     interrupts running JS via Hermes' async timeout. Destruction calls it.
//   - running() is true from start() until teardown finishes on the kernel
//     thread.
//   - waitUntilStopped() blocks until teardown finished; it exists for tests
//     and probes only — never call it on a UI thread.
//
// Host integration:
//   - Hooks.beforeEvaluate runs on the kernel thread after globals install and
//     before the script evaluates.
//   - Hooks.onPost receives bytes the script posts via __qntx.post.
//   - Hooks.onError receives a single fatal error (script exception, task
//     exception, unhandled rejection); the runtime is torn down afterwards.
//     Errors that only exist because shutdown was requested never reach it.
class KernelRuntime final : public std::enable_shared_from_this<KernelRuntime> {
 public:
  struct Hooks {
    std::function<void(facebook::jsi::Runtime&)> beforeEvaluate;
    std::function<void(std::vector<uint8_t>)> onPost;
    std::function<void(std::string)> onError;
  };

  static std::shared_ptr<KernelRuntime> start(
      KernelScript script,
      Hooks hooks,
      KernelProfile profile = KernelProfile::standard);

  ~KernelRuntime();

  KernelRuntime(const KernelRuntime&) = delete;
  KernelRuntime& operator=(const KernelRuntime&) = delete;
  KernelRuntime(KernelRuntime&&) = delete;
  KernelRuntime& operator=(KernelRuntime&&) = delete;

  // Delivers bytes to the script's message handler. Safe after destroy():
  // returns immediately if the runtime is stopping or gone.
  void post(std::vector<uint8_t> bytes);

  void destroy() noexcept;
  bool running() const noexcept;
  bool waitUntilStopped(std::chrono::milliseconds timeout) const;

 private:
  struct Impl;

  KernelRuntime();

  std::shared_ptr<Impl> impl_;
};

} // namespace qntx
