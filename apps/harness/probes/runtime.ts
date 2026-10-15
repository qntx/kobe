import { postJson } from "./share";

const PROBED = [
  "TextEncoder",
  "TextDecoder",
  "crypto",
  "queueMicrotask",
  "setTimeout",
  "setInterval",
  "URL",
  "URLSearchParams",
  "atob",
  "btoa",
  "Intl",
  "performance",
  "structuredClone",
  "FinalizationRegistry",
  "AbortController",
  "fetch",
  "indexedDB",
  "Buffer",
  "console",
] as const;

// Bracket access, not Reflect: hardenedHermesRuntimeConfig() drops Reflect
// and this probe must still run to report what else is missing.
const has = (name: string): boolean =>
  (globalThis as unknown as Record<string, unknown>)[name] !== undefined;

const tryCall = (fn: () => unknown): { throws: boolean; message?: string } => {
  try {
    fn();
    return { throws: false };
  } catch (e) {
    return { throws: true, message: String(e) };
  }
};

const stats = (values: number[]): Record<string, number> => {
  const sorted = [...values].sort((a, b) => a - b);
  const pick = (p: number): number =>
    sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)] ?? 0;
  return {
    n: sorted.length,
    median: pick(50),
    p95: pick(95),
    min: sorted[0] ?? 0,
    max: sorted[sorted.length - 1] ?? 0,
  };
};

const wait = (ms: number): Promise<void> =>
  new Promise((resolve) => {
    __qntx.setTimer(ms, resolve);
  });

const measureTimer = async (delayMs: number, samples: number): Promise<Record<string, number>> => {
  const deltas: number[] = [];
  for (let i = 0; i < samples; i++) {
    const t0 = __qntx.now();
    await wait(delayMs);
    deltas.push(__qntx.now() - t0 - delayMs);
  }
  return stats(deltas);
};

const main = async (): Promise<void> => {
  const globals = Object.fromEntries(PROBED.map((name) => [name, has(name)]));
  const evalResult = tryCall(() => {
    (0, eval)("1");
  });
  const functionResult = tryCall(() => {
    void new Function("return 1")();
  });
  const runtimeProps =
    typeof HermesInternal === "object" && HermesInternal !== null
      ? (HermesInternal.getRuntimeProperties?.() ?? {})
      : {};
  const random = __qntx.random(32);
  const timer10 = await measureTimer(10, 10);
  const timer100 = await measureTimer(100, 10);
  let cancelledFired = false;
  const cancel = __qntx.setTimer(20, () => {
    cancelledFired = true;
  });
  cancel();
  await wait(80);
  postJson({
    kind: "runtime",
    globals,
    hermesInternal: typeof HermesInternal === "object" && HermesInternal !== null,
    bytecodeVersion: runtimeProps["Bytecode Version"] ?? null,
    eval: evalResult,
    functionCtor: functionResult,
    random: { length: random.length, isUint8Array: random instanceof Uint8Array },
    timer10MsError: timer10,
    timer100MsError: timer100,
    timerCancelWorks: !cancelledFired,
  });
};

main().catch((e: unknown) => {
  postJson({ kind: "runtime", fatal: String(e) });
});
