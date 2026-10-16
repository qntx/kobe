import { NitroModules } from "react-native-nitro-modules";

import type { V1Probe } from "./specs/v1-probe.nitro.ts";

const probe = NitroModules.createHybridObject<V1Probe>("V1Probe");

/** Run one V1 probe; resolves with its JSON result. mode is "source" | "bytecode". */
export const runProbe = (probeName: string, mode: string): Promise<string> =>
  probe.run(probeName, mode);

/** Start a long-lived kernel running `probe`; resolves on its first post (ready). */
export const openKernel = (probeName: string, mode: string): Promise<void> =>
  probe.openKernel(probeName, mode);

/** Post to the open kernel; resolves with the kernel's next post. Serialized FIFO. */
export const sendToKernel = (message: ArrayBuffer): Promise<ArrayBuffer> =>
  probe.send(message);

/** Destroy the open kernel. Idempotent. */
export const closeKernel = (): void => probe.closeKernel();

/** Print `V1_RESULT {probe, mode, ok, result|error, provenance}` on the native probe channel. */
export const report = (probeName: string, mode: string, ok: boolean, payload: string): void =>
  probe.report(probeName, mode, ok, payload);
