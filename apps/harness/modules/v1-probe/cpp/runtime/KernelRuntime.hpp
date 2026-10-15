#pragma once

#include <hermes/hermes.h>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace qntx {

// Script body handed to the kernel runtime. `bytes` stays alive for the
// runtime's lifetime: Hermes may read lazily-compiled bytecode lazily.
struct KernelScript {
  enum class Kind { source, bytecode };

  Kind kind;
  std::shared_ptr<const std::vector<uint8_t>> bytes;
};

// One dedicated std::thread owning a Hermes runtime, an immediate task queue
// and a deadline-ordered timer queue. All JSI access happens on that thread.
class KernelRuntime final : public std::enable_shared_from_this<KernelRuntime> {
 public:
  struct Hooks {
    // Runs on the kernel thread after __qntx is installed and before the
    // script evaluates; install additional capabilities here (e.g. Nitro).
    std::function<void(facebook::jsi::Runtime&)> beforeEvaluate;
    // Runs on the kernel thread when the kernel invokes __qntx.post. The host
    // owns hopping back to its own thread.
    std::function<void(std::vector<uint8_t>)> onPost;
    // Runs on the kernel thread when the kernel fails: an uncaught script
    // exception, an exception thrown by a task or timer callback, or an
    // unhandled promise rejection. The runtime tears itself down right after.
    std::function<void(std::string)> onError;
  };

  static std::shared_ptr<KernelRuntime> start(
      const hermes::vm::RuntimeConfig& config,
      KernelScript script,
      Hooks hooks);

  ~KernelRuntime();
  KernelRuntime(const KernelRuntime&) = delete;
  KernelRuntime& operator=(const KernelRuntime&) = delete;
  KernelRuntime(KernelRuntime&&) = delete;
  KernelRuntime& operator=(KernelRuntime&&) = delete;

  // Queue a message for the kernel. Safe to call from any thread while the
  // runtime is running; returns silently once destroyed.
  void post(std::vector<uint8_t> bytes);

  // Stop the queues, destroy the runtime on the kernel thread and join it.
  // Idempotent and safe from any thread, including the kernel thread.
  void destroy();

  bool running() const noexcept;

 private:
  struct Impl;
  KernelRuntime();

  std::shared_ptr<Impl> impl_;
};

} // namespace qntx
