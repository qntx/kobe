import { NitroModules } from "react-native-nitro-modules";

import type { V1Probe } from "./specs/v1-probe.nitro.ts";

const probe = NitroModules.createHybridObject<V1Probe>("V1Probe");

/** Run one V1 probe; resolves with its JSON result. mode is "source" | "bytecode". */
export const runProbe = (probeName: string, mode: string): Promise<string> =>
  probe.run(probeName, mode);

/** Print `V1_RESULT <line>` on the native probe channel (stderr / logcat V1Probe). */
export const emitResultLine = (line: string): void => probe.emit(line);
