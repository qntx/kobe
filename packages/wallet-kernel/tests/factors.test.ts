import { hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { base64urlnopad } from "@scure/base";
import { describe, expect, it } from "vite-plus/test";

import { Secret } from "../src/secret/secret.ts";
import {
  assertPasswordPolicy,
  passkeyKek,
  passwordKek,
  unwrapDek,
  wrapDek,
} from "../src/vault/factors.ts";
import { encodeHeader } from "../src/vault/headers.ts";
import type { PasswordFactorHeader } from "../src/vault/headers.ts";
import type { StoredFactor } from "../src/vault/store.ts";
import { fixedRandom, kernelError, loadVectors, subtlePbkdf2 } from "./helpers.ts";

type FactorsVectors = {
  password: Array<{
    password: string;
    nfkcPassword: string;
    salt: string;
    iterations: number;
    kek: string;
  }>;
  passkey: { prf: string; credentialId: string; kek: string };
};
const vectors = loadVectors("factors.json") as FactorsVectors;

const passwordHeader: PasswordFactorHeader = {
  salt: "ABEiM0RVZneImaq7zN3u_w",
  iterations: 600_000,
  createdAt: 1_767_225_600_000,
};
const factorRef = {
  kind: "password" as const,
  id: "00112233445566778899aabbccddeeff",
  header: encodeHeader(passwordHeader),
};

async function kekOf(vector: (typeof vectors.password)[number]): Promise<Uint8Array> {
  return passwordKek(
    utf8ToBytes(vector.password),
    base64urlnopad.decode(vector.salt),
    subtlePbkdf2,
  );
}

describe("passwordKek vectors", () => {
  it.each(vectors.password)("password → $nfkcPassword", async (vector) => {
    await expect(kekOf(vector)).resolves.toStrictEqual(hexToBytes(vector.kek));
  });

  it("rejects passwords shorter than 10 code points after NFKC", () => {
    expect(kernelError(() => assertPasswordPolicy(utf8ToBytes("ﬀ1234567")))).toBe("invalid-input");
    expect(kernelError(() => assertPasswordPolicy(utf8ToBytes("correct horse")))).toBeUndefined();
  });
});

describe("passkeyKek vector", () => {
  it("matches and wipes the PRF", () => {
    const prf = hexToBytes(vectors.passkey.prf);
    const kek = passkeyKek(prf, base64urlnopad.decode(vectors.passkey.credentialId));
    expect(kek).toStrictEqual(hexToBytes(vectors.passkey.kek));
    expect(prf.every((b) => b === 0)).toBe(true);
  });
});

describe("wrap/unwrap DEK", () => {
  const nonce = fixedRandom(new Uint8Array(24).fill(9));

  it("round trips", async () => {
    const kek = await kekOf(vectors.password[0]!);
    const dek = Secret.take(new Uint8Array(32).fill(7));
    const sealed = wrapDek(kek, dek, factorRef, nonce);
    const stored: StoredFactor = { ...factorRef, sealed };
    const opened = unwrapDek(kek, stored);
    opened.use((bytes) => expect(bytes).toStrictEqual(new Uint8Array(32).fill(7)));
    opened.wipe();
    dek.wipe();
  });

  it("fails with the wrong KEK", async () => {
    const kek = await kekOf(vectors.password[0]!);
    const otherKek = await kekOf(vectors.password[1]!);
    const dek = Secret.take(new Uint8Array(32).fill(7));
    const stored: StoredFactor = { ...factorRef, sealed: wrapDek(kek, dek, factorRef, nonce) };
    expect(kernelError(() => unwrapDek(otherKek, stored))).toBe("integrity");
    dek.wipe();
  });

  it("fails when the header belongs to another factor", async () => {
    const kek = await kekOf(vectors.password[0]!);
    const dek = Secret.take(new Uint8Array(32).fill(7));
    const stored: StoredFactor = {
      ...factorRef,
      sealed: wrapDek(kek, dek, factorRef, nonce),
      header: encodeHeader({ credentialId: "3q2-78r-", createdAt: 0 }),
    };
    expect(kernelError(() => unwrapDek(kek, stored))).toBe("integrity");
    dek.wipe();
  });
});
