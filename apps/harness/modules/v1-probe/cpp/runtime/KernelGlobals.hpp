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
// thread — background threads never touch it.
struct KernelPendingCall {
  std::optional<facebook::jsi::Function> done;
};

// Defined in KernelGlobals.cpp: captured JS intrinsics (defineProperty,
// freeze, %TypedArray%.prototype getters, the Uint8Array constructor, …) that
// host functions call instead of looking properties up on possibly-tampered
// objects.
struct KernelIntrinsics;

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
  // cancellation closure: calling it on the kernel thread erases the entry
  // immediately, releasing the stored jsi::Function. Both are kernel-thread
  // only — timers never cross threads.
  using TimerCancel = std::function<void()>;
  std::function<TimerCancel(std::chrono::steady_clock::time_point, facebook::jsi::Function)>
      scheduleTimer;

  // Enqueues a task that runs fn(rt) on the kernel thread. Callable from any
  // thread — background completions use it to return to the runtime.
  std::function<void(std::function<void(facebook::jsi::Runtime&)>)> enqueueTask;

  // True while the owning runtime is alive. Cleared in teardown AFTER pending
  // callbacks are dropped, so a KDF worker that sees false may safely release
  // its job (and the parked KernelPendingCall) off the kernel thread.
  std::shared_ptr<std::atomic_bool> active;

  // Callbacks parked for in-flight async platform calls. Kernel thread only;
  // teardown clears every `done` before the runtime is destroyed.
  std::unordered_set<std::shared_ptr<KernelPendingCall>> pending;

  // Captured intrinsics for the host functions. Kernel thread only; teardown
  // resets it while the runtime is still alive.
  std::shared_ptr<KernelIntrinsics> intrinsics;

  // Kernel-side handler for bytes delivered by KernelRuntime::post; installed
  // by the script through __qntx.setMessageHandler. Kernel thread only.
  std::optional<facebook::jsi::Function> messageHandler;
};

// Installs the kernel's capabilities on a fresh runtime:
//   globalThis.__qntx   frozen { random, now, elapsed, setTimer, pbkdf2, post,
//                              setMessageHandler }
//   globalThis.crypto   frozen { getRandomValues }
//   globalThis.TextDecoder   UTF-8 only, WHATWG fatal/replacement semantics
//   globalThis.setTimeout / clearTimeout   id-based, kernel-thread timers —
//     Hermes' bundled promise rejection tracker resolves these literals at
//     call time to defer onUnhandled; Promise.then/async use the engine queue
//     and need no globals (measured).
// Each is installed via Object.defineProperty as non-writable,
// non-configurable and non-enumerable.
//
// Also evaluates the kernel prelude — a function expression invoked once with
// a private `natives` object { setTimer, decodeUtf8, reportUnhandled }. Private
// natives are never reachable from globalThis.
void installKernelGlobals(
    facebook::jsi::Runtime& runtime,
    const std::shared_ptr<KernelGlobalsState>& state);

} // namespace qntx
