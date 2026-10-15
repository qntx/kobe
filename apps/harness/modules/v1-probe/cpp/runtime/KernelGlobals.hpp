#pragma once

#include <jsi/jsi.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace qntx {

// A JSI callback parked while an async platform call (e.g. pbkdf2) runs on a
// background thread. `done` is only read, moved or cleared on the kernel
// thread — the background thread never touches it.
struct KernelPendingCall {
  std::optional<facebook::jsi::Function> done;
};

// Shared state between the host functions installed by installKernelGlobals
// and the owning KernelRuntime. The jsi members must only be touched on the
// kernel thread; KernelRuntime clears them before destroying the runtime.
struct KernelGlobalsState {
  // Copies the posted bytes out of the runtime and reports them to the host.
  std::function<void(std::vector<uint8_t>)> postToHost;

  // Records a fatal kernel failure reported by JS (unhandled promise
  // rejection). The runtime tears down after the current task drains.
  std::function<void(std::string)> reportFatal;

  // Schedules fn at deadline on the kernel task queue. Returns the
  // cancellation flag: setting it prevents the task from running.
  using TimerCancel = std::shared_ptr<std::atomic_bool>;
  std::function<TimerCancel(std::chrono::steady_clock::time_point, facebook::jsi::Function)>
      scheduleTimer;

  // Enqueues a task that runs fn(rt) on the kernel thread. Callable from any
  // thread — background completions use it to return to the runtime.
  std::function<void(std::function<void(facebook::jsi::Runtime&)>)> enqueueTask;

  // Callbacks parked for in-flight async platform calls. Kernel thread only;
  // teardown clears every `done` before the runtime is destroyed.
  std::unordered_set<std::shared_ptr<KernelPendingCall>> pending;

  // Kernel-side handler for bytes delivered by KernelRuntime::post; installed
  // by the script through __qntx.setMessageHandler. Kernel thread only.
  std::optional<facebook::jsi::Function> messageHandler;
};

// Installs the frozen __qntx object on the runtime's global:
//   random(length)            Uint8Array via arc4random_buf
//   now()                     wall-clock milliseconds
//   setTimer(delayMs, fn)     returns a cancellation function
//   pbkdf2(hash, pw, salt, i, len, done)   off-thread PBKDF2, done(result, error)
//   post(ArrayBuffer)         forwards bytes to the host
//   setMessageHandler(fn)     registers the host-to-kernel message handler
// and the internal __qntxUnhandledRejection hook used by the rejection
// tracker KernelRuntime evaluates before the script.
void installKernelGlobals(
    facebook::jsi::Runtime& runtime,
    const std::shared_ptr<KernelGlobalsState>& state);

} // namespace qntx
