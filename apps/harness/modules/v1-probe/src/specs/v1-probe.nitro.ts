import type { HybridObject } from "react-native-nitro-modules";

/**
 * V1 kernel-runtime probe driver. `run` executes one probe inside a dedicated
 * Hermes runtime and resolves with the JSON the probe posted (or the JSON the
 * native measurement harness produced). `mode` is "source" or "bytecode" and
 * selects how the embedded probe script is loaded. Rejects with the error
 * message when the probe runtime crashes or the run times out.
 */
export interface V1Probe extends HybridObject<{ ios: "c++"; android: "c++" }> {
  run(probe: string, mode: string): Promise<string>;
  /** Print `V1_RESULT <line>` on the native probe channel (stderr / logcat V1Probe). */
  emit(line: string): void;
}
