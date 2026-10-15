/**
 * Tiny Nitro probe used for the create/destroy churn: install happened in beforeEvaluate, create
 * one NostrNative HybridObject, sign+verify once, post done. V1Probe destroys this runtime and
 * starts the next, so each run exercises the full Nitro-in-kernel lifecycle.
 */
import { schnorr } from "@noble/curves/secp256k1.js";
import { bytesToHex } from "@noble/hashes/utils.js";

import { postJson } from "./share.ts";

try {
  postJson({ kind: "nitro-ready" });
  if (NitroModulesProxy === undefined) {
    throw new Error("NitroModulesProxy missing");
  }
  const native = NitroModulesProxy.createHybridObject("NostrNative");
  const sk = __qntx.random(32);
  const id = __qntx.random(32);
  const aux = __qntx.random(32);
  const sig = new Uint8Array(native.sign(id.buffer as ArrayBuffer, sk.buffer as ArrayBuffer, aux.buffer as ArrayBuffer));
  const js = schnorr.sign(id, sk, aux);
  if (bytesToHex(sig) !== bytesToHex(js)) {
    throw new Error("nitro-ping sign mismatch");
  }
  postJson({ kind: "done", pass: true });
} catch (error: unknown) {
  postJson({ kind: "done", pass: false, error: String(error) });
}
