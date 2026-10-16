/**
 * Phase D probe: Nitro HybridObjects inside the isolated kernel runtime. V1Probe installs
 * `margelo::nitro::install(runtime)` before this script evaluates (no dispatcher, sync methods
 * only). Byte-compares NostrNative.sign against @noble/curves schnorr with the same auxRand, checks
 * verifySerialized, times native vs pure-JS, then keeps signing in setTimer batches until
 * `NITRO_LOOP_MS` total elapsed — the JS side hammers the main-runtime NostrNative meanwhile.
 */
// globals.ts MUST evaluate first: on Hermes versions without a native decoder it
// installs the TextDecoder shim that @qntx/nostr (serializeEvent/getEventHash
// internals) touches inside the bare kernel runtime.
// Reference an export — wallet-worker is `sideEffects: false`, a bare import is tree-shaken.
import { hermesGlobalsInstalled } from "../../../packages/wallet-worker/tests/hermes/globals.ts";

import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { getEventHash, serializeEvent, verifyEvent } from "@qntx/nostr";
import type { Event, UnsignedEvent } from "@qntx/nostr";

import { postJson } from "./share.ts";

const ACCURACY_ITERATIONS = 1000;
const NITRO_LOOP_MS = 5000;

const asBuffer = (view: Uint8Array): ArrayBuffer =>
  view.buffer instanceof ArrayBuffer && view.byteOffset === 0 && view.byteLength === view.buffer.byteLength
    ? view.buffer
    : (new Uint8Array(view).buffer as ArrayBuffer);

const median = (xs: number[]): number => {
  const s = [...xs].sort((a, b) => a - b);
  return s.length === 0 ? 0 : (s[Math.floor((s.length - 1) / 2)] ?? 0);
};
const p95 = (xs: number[]): number => {
  const s = [...xs].sort((a, b) => a - b);
  return s.length === 0 ? 0 : (s[Math.min(s.length - 1, Math.ceil(0.95 * s.length) - 1)] ?? 0);
};

async function main(): Promise<void> {
  if (!hermesGlobalsInstalled) {
    throw new Error("globals module did not evaluate first");
  }
  if (NitroModulesProxy === undefined) {
    throw new Error("NitroModulesProxy missing — nitro was not installed before evaluate");
  }
  const native = NitroModulesProxy.createHybridObject("NostrNative");

  const secretKey = __qntx.random(32);
  const pubkeyNative = new Uint8Array(native.publicKey(asBuffer(secretKey)));
  const pubkeyJs = schnorr.getPublicKey(secretKey);
  if (bytesToHex(pubkeyNative) !== bytesToHex(pubkeyJs)) {
    throw new Error(`publicKey mismatch: ${bytesToHex(pubkeyNative)} != ${bytesToHex(pubkeyJs)}`);
  }

  const signNativeMs: number[] = [];
  const signJsMs: number[] = [];
  const verifyNativeMs: number[] = [];
  const verifyJsMs: number[] = [];
  let mismatches = 0;
  let verifyFailures = 0;
  let jsVerifyFailures = 0;

  const unsigned: UnsignedEvent = {
    pubkey: bytesToHex(pubkeyJs),
    kind: 1,
    created_at: 1_700_000_000,
    tags: [["t", "nitro"]],
    content: "v1 nitro probe",
  };

  const tLoop0 = __qntx.now();
  for (let i = 0; i < ACCURACY_ITERATIONS; i++) {
    const auxRand = __qntx.random(32);

    const draft: UnsignedEvent = {
      ...unsigned,
      content: `v1 nitro probe ${i}`,
      created_at: 1_700_000_000 + i,
    };
    const serialized = utf8ToBytes(serializeEvent(draft));
    const id = sha256(serialized);
    if (bytesToHex(id) !== getEventHash(draft)) {
      throw new Error("sha256(serialized) != getEventHash");
    }

    const t0 = __qntx.now();
    const nativeSig = new Uint8Array(native.sign(asBuffer(id), asBuffer(secretKey), asBuffer(auxRand)));
    const t1 = __qntx.now();
    const jsSig = schnorr.sign(id, secretKey, auxRand);
    const t2 = __qntx.now();
    signNativeMs.push(t1 - t0);
    signJsMs.push(t2 - t1);
    if (bytesToHex(nativeSig) !== bytesToHex(jsSig)) mismatches += 1;

    const t3 = __qntx.now();
    const okNative = native.verifySerialized(
      asBuffer(serialized),
      asBuffer(id),
      asBuffer(pubkeyJs),
      asBuffer(nativeSig),
    );
    const t4 = __qntx.now();
    verifyNativeMs.push(t4 - t3);
    if (!okNative) verifyFailures += 1;

    if (i % 10 === 0) {
      const event = { ...draft, id: bytesToHex(id), sig: bytesToHex(nativeSig) } as Event;
      const t5 = __qntx.now();
      const okJs = verifyEvent(event);
      verifyJsMs.push(__qntx.now() - t5);
      if (!okJs) jsVerifyFailures += 1;
    }

    // Yield so timer/message tasks interleave with the accuracy loop.
    if (i % 100 === 99) {
      await new Promise<void>((resolve) => __qntx.setTimer(0, resolve));
    }
  }

  // Keep the kernel busy with native sign+verify while the JS side creates/destroys
  // other Nitro-installed runtimes and hammers the main-runtime NostrNative. The window
  // starts after the accuracy loop; the JS side keeps hammering until this probe resolves.
  const stressUntil = __qntx.now() + NITRO_LOOP_MS;
  let extra = 0;
  while (__qntx.now() < stressUntil) {
    for (let batch = 0; batch < 200 && __qntx.now() < stressUntil; batch++) {
      const auxRand = __qntx.random(32);
      const id = __qntx.random(32);
      const sig = new Uint8Array(native.sign(asBuffer(id), asBuffer(secretKey), asBuffer(auxRand)));
      const serialized = utf8ToBytes(serializeEvent({ ...unsigned, content: `stress ${extra}` }));
      const ok = native.verifySerialized(
        asBuffer(serialized),
        asBuffer(id),
        asBuffer(pubkeyJs),
        asBuffer(sig),
      );
      void ok;
      extra += 1;
    }
    await new Promise<void>((resolve) => __qntx.setTimer(0, resolve));
  }

  postJson({
    kind: "done",
    pass: mismatches === 0 && verifyFailures === 0 && jsVerifyFailures === 0,
    iterations: ACCURACY_ITERATIONS,
    extraIterations: extra,
    signMismatches: mismatches,
    verifySerializedFailures: verifyFailures,
    verifyEventFailures: jsVerifyFailures,
    signNative: { n: signNativeMs.length, median: median(signNativeMs), p95: p95(signNativeMs) },
    signJs: { n: signJsMs.length, median: median(signJsMs), p95: p95(signJsMs) },
    verifyNative: { n: verifyNativeMs.length, median: median(verifyNativeMs), p95: p95(verifyNativeMs) },
    verifyJs: { n: verifyJsMs.length, median: median(verifyJsMs), p95: p95(verifyJsMs) },
    durationMs: __qntx.now() - tLoop0,
  });
}

try {
  postJson({ kind: "nitro-ready" });
  main().catch((error: unknown) => {
    postJson({
      kind: "done",
      pass: false,
      error: error instanceof Error ? `${error.name}: ${error.message}` : String(error),
    });
  });
} catch (error: unknown) {
  postJson({ kind: "done", pass: false, error: String(error) });
}
