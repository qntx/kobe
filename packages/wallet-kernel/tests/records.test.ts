import { hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vite-plus/test";

import { encodeNostrKeyHeader, parseNostrKeyHeader } from "../src/modules/nostr/record.ts";
import type { KernelPlatform } from "../src/platform.ts";
import {
  encodeHeader,
  parseDataKeyHeader,
  parseEntropyHeader,
  parsePasskeyFactorHeader,
  parsePasswordFactorHeader,
} from "../src/vault/headers.ts";
import { createMemoryStore } from "../src/vault/memory.ts";
import type { StoreOp, StoredFactor } from "../src/vault/store.ts";
import { establishOps } from "../src/vault/vault.ts";
import { fixedRandom, loadVectors, subtlePbkdf2 } from "./helpers.ts";

type VectorCase = {
  readonly name: string;
  readonly kind: string;
  readonly input: Record<string, unknown>;
  readonly text: string;
};
const { vectors } = loadVectors("records.json") as { vectors: VectorCase[] };
const byKind = (kind: string): VectorCase[] => vectors.filter((v) => v.kind === kind);

describe("record and factor header vectors", () => {
  it.each(byKind("entropy"))("$name encodes and parses byte-for-byte", (vector) => {
    const parsed = parseEntropyHeader(vector.text);
    expect(parsed).toStrictEqual(vector.input);
    expect(encodeHeader(parsed)).toBe(vector.text);
  });

  it.each(byKind("data-key"))("$name encodes and parses byte-for-byte", (vector) => {
    const parsed = parseDataKeyHeader(vector.text);
    expect(parsed).toStrictEqual(vector.input);
    expect(encodeHeader(parsed)).toBe(vector.text);
  });

  it.each(vectors.filter((v) => v.kind.startsWith("nostr-")))(
    "$name encodes and parses byte-for-byte",
    (vector) => {
      const parsed = parseNostrKeyHeader(vector.text);
      expect(parsed).toStrictEqual(vector.input);
      expect(encodeNostrKeyHeader(parsed)).toBe(vector.text);
    },
  );

  it.each(byKind("factor-password"))("$name encodes and parses byte-for-byte", (vector) => {
    const parsed = parsePasswordFactorHeader(vector.text);
    expect(parsed).toStrictEqual(vector.input);
    expect(encodeHeader(parsed)).toBe(vector.text);
  });

  it.each(byKind("factor-passkey"))("$name encodes and parses byte-for-byte", (vector) => {
    const parsed = parsePasskeyFactorHeader(vector.text);
    expect(parsed).toStrictEqual(vector.input);
    expect(encodeHeader(parsed)).toBe(vector.text);
  });
});

const metaVector = vectors.find((v) => v.kind === "meta");
const metaKeyId = metaVector?.input["keyId"];
if (metaVector === undefined || typeof metaKeyId !== "string") {
  throw new Error("records.json has no meta vector with a string keyId");
}

function initMeta(ops: StoreOp[]) {
  const [init] = ops;
  if (init === undefined || init.op !== "init") {
    throw new Error("establishOps produced no init op");
  }
  return init.meta;
}

describe("vault meta vector", () => {
  it("establishOps writes the vector meta shape and key order", () => {
    const platform: KernelPlatform = {
      random: fixedRandom(hexToBytes(metaKeyId)),
      now: () => 0,
      elapsed: () => 0,
      setTimer: () => () => {},
      pbkdf2: subtlePbkdf2,
      store: createMemoryStore(),
      policy: { idleMs: 0, maxSessionMs: 0, maxScryptLogN: 20, activity: "presence" },
    };
    const factor: StoredFactor = {
      kind: "password",
      id: "00112233445566778899aabbccddeeff",
      header: "{}",
      sealed: new Uint8Array([0x02]),
    };
    const { ops } = establishOps(platform, factor, []);
    const meta = initMeta(ops);
    expect(meta).toStrictEqual(metaVector.input);
    expect(JSON.stringify(meta)).toBe(metaVector.text);
  });
});
