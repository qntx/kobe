import { useEffect, useState } from "react";
import { SafeAreaView, ScrollView, StyleSheet, Text, View } from "react-native";

import { NitroModules } from "react-native-nitro-modules";

import { emitResultLine, runProbe } from "@qntx/v1-probe";

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
];

type MainNostr = {
  readonly publicKey: (secretKey: ArrayBuffer) => ArrayBuffer;
  readonly sign: (id: ArrayBuffer, secretKey: ArrayBuffer, auxRand: ArrayBuffer) => ArrayBuffer;
};

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

// Emits one extra V1_RESULT line that merges the kernel-side nitro result with main-runtime
// hammer and create/destroy churn stats. The hammer and churn run until the kernel nitro
// probe resolves, so the kernel's stress window overlaps real Nitro traffic from this runtime.
const runNitroStress = async (mode: string): Promise<ProbeResult> => {
  const trace = (step: string): void => {
    emitResultLine(JSON.stringify({ probe: "nitro-stress-trace", mode, step }));
  };
  trace("start");
  let kernelDone = false;
  const kernel = runProbe("nitro", mode)
    .then((json) => ({ ok: true as const, json }))
    .catch((e) => ({ ok: false as const, json: String(e) }))
    .finally(() => {
      kernelDone = true;
      trace("kernel-settled");
    });
  const [kernelResult, hammer, churn] = await Promise.all([
    kernel.then((r) => (trace("kernel-await"), r)),
    mainRuntimeHammer(() => kernelDone).then(
      (r) => (trace("hammer-done"), r),
      (e) => (trace(`hammer-error:${String(e)}`), { mainRuntimeSignCalls: -1, mainRuntimeSignErrors: -1 }),
    ),
    churnKernels(mode, () => kernelDone).then(
      (r) => (trace("churn-done"), r),
      (e) => (trace(`churn-error:${String(e)}`), { churnCycles: -1, churnErrors: -1 }),
    ),
  ]);
  trace("all-resolved");
  const merged = JSON.stringify({
    probe: "nitro-stress",
    mode,
    ok: kernelResult.ok,
    kernel: kernelResult.json,
    ...hammer,
    ...churn,
  });
  try {
    emitResultLine(merged);
  } catch (e) {
    emitResultLine(
      JSON.stringify({ probe: "nitro-stress", mode, ok: false, error: `emit failed: ${String(e)}` }),
    );
  }
  return {
    probe: "nitro-stress",
    mode,
    ok: kernelResult.ok,
    summary: `${hammer.mainRuntimeSignCalls} main calls, ${churn.churnCycles} churn cycles`,
  };
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
      emitResultLine(JSON.stringify({ probe: "emit-selftest", mode: "source", ok: true }));
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
      emitResultLine(
        JSON.stringify({ probe: "run-failed", mode: "source", ok: false, error: String(e) }),
      );
    });
    return () => {
      cancelled = true;
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
