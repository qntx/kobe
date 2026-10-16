import { useEffect, useState } from "react";
import { SafeAreaView, ScrollView, StyleSheet, Text, View } from "react-native";

import { NitroModules } from "react-native-nitro-modules";
import type { HybridObject } from "react-native-nitro-modules";

import { closeKernel, openKernel, report, runProbe, sendToKernel } from "@qntx/v1-probe";

type ProbeResult = {
  probe: string;
  mode: string;
  ok: boolean;
  summary: string;
};

const PROBES: ReadonlyArray<readonly [string, string]> = [
  ["runtime", "source"],
  ["runtime", "bytecode"],
  ["startup", "source"],
  ["startup", "bytecode"],
  ["roundtrip", "source"],
  ["roundtrip", "bytecode"],
  ["lifecycle", "source"],
  ["lifecycle", "bytecode"],
  ["crash-sync", "source"],
  ["crash-promise", "source"],
  ["hardened", "source"],
  ["kernel", "source"],
  ["kernel", "bytecode"],
  ["kernel-hardened", "source"],
  ["kernel-hardened", "bytecode"],
];

interface MainNostr extends HybridObject<{ ios: "c++"; android: "c++" }> {
  readonly publicKey: (secretKey: ArrayBuffer) => ArrayBuffer;
  readonly sign: (id: ArrayBuffer, secretKey: ArrayBuffer, auxRand: ArrayBuffer) => ArrayBuffer;
}

// Hammers the main runtime's own NostrNative while the kernel-side nitro probe loops on its
// thread; yields between batches so other JS work (churn runs) interleaves. Runs until
// `done()` reports the kernel probe finished.
const mainRuntimeHammer = async (done: () => boolean): Promise<Record<string, number>> => {
  const native = NitroModules.createHybridObject<MainNostr>("NostrNative");
  const sk = new Uint8Array(32);
  const id = new Uint8Array(32);
  const aux = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    sk[i] = (i * 31 + 7) & 0xff;
    id[i] = (i * 17 + 3) & 0xff;
    aux[i] = (i * 13 + 1) & 0xff;
  }
  let calls = 0;
  let errors = 0;
  const skBuf = sk.buffer as ArrayBuffer;
  const idBuf = id.buffer as ArrayBuffer;
  const auxBuf = aux.buffer as ArrayBuffer;
  while (!done()) {
    for (let i = 0; i < 50; i++) {
      try {
        native.sign(idBuf, skBuf, auxBuf);
        calls += 1;
      } catch {
        errors += 1;
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  return { mainRuntimeSignCalls: calls, mainRuntimeSignErrors: errors };
};

// Sequential create/destroy of Nitro-installed kernel runtimes while `mainRuntimeHammer` keeps
// calling Nitro on the main runtime.
const churnKernels = async (mode: string, done: () => boolean): Promise<Record<string, number>> => {
  let cycles = 0;
  let errors = 0;
  while (cycles < 50 && !done()) {
    try {
      await runProbe("nitro-ping", mode);
      cycles += 1;
    } catch {
      errors += 1;
    }
  }
  return { churnCycles: cycles, churnErrors: errors };
};

// Emits one V1_RESULT line via report() that merges the kernel-side nitro result with
// main-runtime hammer and create/destroy churn stats. The hammer and churn run until the
// kernel nitro probe resolves, so the kernel's stress window overlaps real Nitro traffic
// from this runtime.
const runNitroStress = async (mode: string): Promise<ProbeResult> => {
  let kernelDone = false;
  const kernel = runProbe("nitro", mode)
    .then((json) => ({ ok: true as const, json }))
    .catch((e) => ({ ok: false as const, json: String(e) }))
    .finally(() => {
      kernelDone = true;
    });
  const [kernelResult, hammer, churn] = await Promise.all([
    kernel,
    mainRuntimeHammer(() => kernelDone).then(
      (r) => r,
      () => ({ mainRuntimeSignCalls: -1, mainRuntimeSignErrors: -1 }),
    ),
    churnKernels(mode, () => kernelDone).then(
      (r) => r,
      () => ({ churnCycles: -1, churnErrors: -1 }),
    ),
  ]);
  const payload = JSON.stringify({
    kernel: kernelResult.json,
    ...hammer,
    ...churn,
  });
  report("nitro-stress", mode, kernelResult.ok, kernelResult.ok ? payload : String(kernelResult.json));
  return {
    probe: "nitro-stress",
    mode,
    ok: kernelResult.ok,
    summary: `${hammer.mainRuntimeSignCalls} main calls, ${churn.churnCycles} churn cycles`,
  };
};

const percentile = (values: number[], p: number): number => {
  if (values.length === 0) {
    return 0;
  }
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)] ?? 0;
};

type Stats = {
  n: number;
  p50: number;
  p95: number;
  min: number;
  max: number;
};

const stats = (values: number[]): Stats => ({
  n: values.length,
  p50: percentile(values, 50),
  p95: percentile(values, 95),
  min: values.length === 0 ? 0 : Math.min(...values),
  max: values.length === 0 ? 0 : Math.max(...values),
});

// Samples main-thread event-loop lag (actual − expected) with a self-rescheduling
// setTimeout(16) chain until `done()` reports the work finished.
const sampleLag = async (done: () => boolean): Promise<number[]> => {
  const lags: number[] = [];
  let expected = performance.now() + 16;
  while (!done()) {
    await new Promise((resolve) => setTimeout(resolve, 16));
    const now = performance.now();
    lags.push(now - expected);
    expected = now + 16;
  }
  return lags;
};

const sampleLagFor = async (ms: number): Promise<number[]> => {
  const end = performance.now() + ms;
  return sampleLag(() => performance.now() >= end);
};

// Q5: JS-side round-trip timing over openKernel/send (includes the JSI call and the
// CallInvoker hop back) at 1 KiB and 64 KiB, plus main-thread lag while the kernel
// runs a 600k PBKDF2 and a 2 s busy loop vs a 3 s idle baseline.
const runQ5 = async (mode: string): Promise<ProbeResult> => {
  const encoder = new TextEncoder();
  try {
    await openKernel("echo", mode);
    const roundTrips = async (size: number): Promise<Stats> => {
      const message = new Uint8Array(size);
      for (let i = 0; i < size; i++) {
        message[i] = i & 0xff;
      }
      const samples: number[] = [];
      for (let i = 0; i < 200; i++) {
        const t0 = performance.now();
        const reply = await sendToKernel(message.buffer as ArrayBuffer);
        samples.push(performance.now() - t0);
        if (reply.byteLength !== size) {
          throw new Error(`echo returned ${reply.byteLength} bytes for a ${size}-byte message`);
        }
      }
      return stats(samples);
    };
    const rtt1KiB = await roundTrips(1024);
    const rtt64KiB = await roundTrips(64 * 1024);

    const lagIdle = stats(await sampleLagFor(3000));

    closeKernel();
    await openKernel("busy", mode);
    const lagDuring = async (work: "kdf" | "spin"): Promise<Stats> => {
      let finished = false;
      let failure: unknown;
      const workDone = sendToKernel(encoder.encode(work).buffer as ArrayBuffer).then(
        () => {
          finished = true;
        },
        (e: unknown) => {
          finished = true;
          failure = e;
        },
      );
      const lags = await sampleLag(() => finished);
      await workDone;
      if (failure !== undefined) {
        throw failure instanceof Error ? failure : new Error(String(failure));
      }
      return stats(lags);
    };
    const lagKdf = await lagDuring("kdf");
    const lagSpin = await lagDuring("spin");
    closeKernel();

    const payload = JSON.stringify({
      rtt1KiB,
      rtt64KiB,
      lagIdleMs: { p50: lagIdle.p50, p95: lagIdle.p95, max: lagIdle.max },
      lagKdfMs: { p50: lagKdf.p50, p95: lagKdf.p95, max: lagKdf.max },
      lagSpinMs: { p50: lagSpin.p50, p95: lagSpin.p95, max: lagSpin.max },
    });
    report("q5", mode, true, payload);
    return {
      probe: "q5",
      mode,
      ok: true,
      summary: `rtt1KiB p50 ${rtt1KiB.p50.toFixed(2)}ms, lag spin p95 ${lagSpin.p95.toFixed(1)}ms`,
    };
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    report("q5", mode, false, message);
    return { probe: "q5", mode, ok: false, summary: message };
  } finally {
    closeKernel();
  }
};

const summarize = (json: string): string => {
  try {
    const parsed = JSON.parse(json) as Record<string, unknown>;
    if (typeof parsed["error"] === "string") {
      return `error: ${parsed["error"]}`;
    }
    return "ok";
  } catch {
    return json.slice(0, 60);
  }
};

export const App = (): React.JSX.Element => {
  const [results, setResults] = useState<ProbeResult[]>([]);
  const [running, setRunning] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const run = async (): Promise<void> => {
      report("selftest", "source", true, "{}");
      for (const [probe, mode] of PROBES) {
        if (cancelled) {
          return;
        }
        setRunning(`${probe}:${mode}`);
        let entry: ProbeResult;
        try {
          const json = await runProbe(probe, mode);
          entry = { probe, mode, ok: true, summary: summarize(json) };
        } catch (e) {
          entry = { probe, mode, ok: false, summary: String(e) };
        }
        if (!cancelled) {
          setResults((prev) => [...prev, entry]);
        }
      }
      for (const mode of ["source", "bytecode"]) {
        if (cancelled) {
          return;
        }
        setRunning(`q5:${mode}`);
        const entry = await runQ5(mode);
        if (!cancelled) {
          setResults((prev) => [...prev, entry]);
        }
      }
      if (!cancelled) {
        setRunning("nitro-stress");
        const entry = await runNitroStress("source");
        if (!cancelled) {
          setResults((prev) => [...prev, entry]);
          setRunning(null);
          setDone(true);
        }
      }
    };
    run().catch((e: unknown) => {
      report("run-failed", "source", false, e instanceof Error ? e.message : String(e));
    });
    return () => {
      cancelled = true;
      closeKernel();
    };
  }, []);

  return (
    <SafeAreaView style={styles.root}>
      <View style={styles.header}>
        <Text style={styles.title}>V1 kernel runtime probes</Text>
        <Text style={styles.status}>
          {running !== null ? `running ${running}` : done ? `done (${results.length} probes)` : "starting"}
        </Text>
      </View>
      <ScrollView style={styles.list}>
        {results.map((r) => (
          <View key={`${r.probe}:${r.mode}`} style={styles.row}>
            <Text style={styles.probe}>
              {r.probe} [{r.mode}]
            </Text>
            <Text style={r.ok ? styles.ok : styles.fail} numberOfLines={3}>
              {r.summary}
            </Text>
          </View>
        ))}
      </ScrollView>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: "#fff" },
  header: { padding: 16, borderBottomWidth: 1, borderBottomColor: "#ddd" },
  title: { fontSize: 17, fontWeight: "600" },
  status: { marginTop: 4, fontSize: 13, color: "#666" },
  list: { flex: 1, padding: 16 },
  row: { flexDirection: "row", paddingVertical: 6, gap: 8 },
  probe: { width: 160, fontFamily: "Menlo", fontSize: 12 },
  ok: { flex: 1, fontFamily: "Menlo", fontSize: 12, color: "#060" },
  fail: { flex: 1, fontFamily: "Menlo", fontSize: 12, color: "#c00" },
});
