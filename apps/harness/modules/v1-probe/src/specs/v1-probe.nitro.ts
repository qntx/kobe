import type { HybridObject } from "react-native-nitro-modules";

/**
 * V1 kernel-runtime probe driver. `run` executes one probe inside a dedicated
 * Hermes runtime and resolves with the JSON the probe posted (or the JSON the
 * native measurement harness produced). `mode` is "source" or "bytecode" and
 * selects how the embedded probe script is loaded. Rejects with the error
 * message when the probe runtime crashes or the run times out.
 *
 * `openKernel`/`send`/`closeKernel` drive one long-lived kernel runtime for
 * measurements that must time the full JS → kernel → JS round trip on the JS
 * side (Q5). `report` prints a `V1_RESULT` line with provenance attached so
 * JS-originated results are recorded identically to native ones.
 */
export interface V1Probe extends HybridObject<{ ios: "c++"; android: "c++" }> {
  run(probe: string, mode: string): Promise<string>;
  /** Start one kernel runtime running `probe`; resolves on its first post (ready). */
  openKernel(probe: string, mode: string): Promise<void>;
  /**
   * Post `message` to the open kernel; resolves with the kernel's next post as a
   * native-owned ArrayBuffer copy. Calls are serialized FIFO. Rejects when no
   * kernel is open or the kernel failed.
   */
  send(message: ArrayBuffer): Promise<ArrayBuffer>;
  /** Destroy the open kernel. Idempotent. */
  closeKernel(): void;
  /**
   * Print `V1_RESULT {probe, mode, ok, result|error, provenance}` on the native
   * probe channel (stderr / logcat V1Probe). `payload` is the result JSON when
   * `ok`, otherwise the error text.
   */
  report(probe: string, mode: string, ok: boolean, payload: string): void;
}
