import { hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { base64urlnopad } from "@scure/base";
import { describe, expect, it } from "vite-plus/test";

import { KernelError } from "../src/errors.ts";
import type { Random } from "../src/platform.ts";
import { Secret, wipe } from "../src/secret/secret.ts";
import {
  assertPasswordPolicy,
  factorBindingOk,
  factorPublicKey,
  passkeyKek,
  passwordKek,
  unwrapDek,
  wrapDek,
} from "../src/vault/factors.ts";
import type { StoredFactor } from "../src/vault/store.ts";
import { kernelError, loadVectors, subtlePbkdf2 } from "./helpers.ts";

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

type FactorWrapVector = {
  name: string;
  kek: string;
  dek: string;
  eph: string;
  nonce: string;
  kind: string;
  id: string;
  header: string;
  publicKey: string;
  binding: string;
  sealed: string;
};
const wrapVectors = (loadVectors("factor-wrap.json") as { vectors: FactorWrapVector[] }).vectors;

async function kekOf(vector: (typeof vectors.password)[number]): Promise<Uint8Array> {
  return passwordKek(
    utf8ToBytes(vector.password),
    base64urlnopad.decode(vector.salt),
    subtlePbkdf2,
  );
}

/** Deterministic Random for vector reproduction: draws come off `chunks` in order. */
function scriptedRandom(chunks: Uint8Array[]): Random {
  const queue = [...chunks];
  return (length) => {
    const next = queue.shift();
    if (next === undefined || next.length !== length) {
      throw new Error(`unexpected draw of ${length} bytes`);
    }
    return next;
  };
}

const unwrapError = (kek: Uint8Array, stored: StoredFactor): KernelError | undefined => {
  try {
    const dek = unwrapDek(kek, stored);
    dek.wipe();
    return undefined;
  } catch (error) {
    if (error instanceof KernelError) {
      return error;
    }
    throw error;
  }
};

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

describe("factor wrap v2 vectors", () => {
  it.each(wrapVectors)("reproduces the sealed factor row ($name)", (vector) => {
    const publicKey = factorPublicKey(hexToBytes(vector.kek));
    expect(base64urlnopad.encode(publicKey)).toBe(vector.publicKey);
    const dek = Secret.take(hexToBytes(vector.dek));
    const sealed = wrapDek(
      dek,
      publicKey,
      { kind: vector.kind, id: vector.id, header: vector.header },
      scriptedRandom([hexToBytes(vector.eph), hexToBytes(vector.nonce)]),
    );
    expect(sealed).toStrictEqual(hexToBytes(vector.sealed));
    dek.wipe();
  });

  it.each(wrapVectors)("unwraps the vector ($name)", (vector) => {
    const stored: StoredFactor = {
      kind: vector.kind,
      id: vector.id,
      header: vector.header,
      sealed: hexToBytes(vector.sealed),
    };
    const dek = unwrapDek(hexToBytes(vector.kek), stored);
    dek.use((bytes) => expect(bytes).toStrictEqual(hexToBytes(vector.dek)));
    expect(factorBindingOk(dek, stored)).toBe(true);
    dek.wipe();
  });
});

/** Flips one byte of `bytes` at `offset`. */
const flipByte = (bytes: Uint8Array, offset: number): Uint8Array => {
  const copy = new Uint8Array(bytes);
  copy[offset] = (copy[offset] ?? 0) ^ 1;
  return copy;
};

describe("wrap/unwrap failures", () => {
  const vector = wrapVectors[0]!;
  const storedOf = (mutate: (sealed: Uint8Array) => Uint8Array): StoredFactor => ({
    kind: vector.kind,
    id: vector.id,
    header: vector.header,
    sealed: mutate(hexToBytes(vector.sealed)),
  });
  const intact = (): StoredFactor => storedOf((sealed) => sealed);

  it("a wrong password fails the public-key check before any AEAD — wrong-password", async () => {
    const otherKek = await kekOf(vectors.password[1]!);
    try {
      const error = unwrapError(otherKek, intact());
      expect(error?.code).toBe("wrong-password");
      expect(error?.corrupted).toBe(false);
    } finally {
      wipe(otherKek);
    }
  });

  it("a tampered binding byte is corrupted-marked integrity", () => {
    const error = unwrapError(
      hexToBytes(vector.kek),
      storedOf((sealed) => flipByte(sealed, 40)),
    );
    expect(error?.code).toBe("integrity");
    expect(error?.corrupted).toBe(true);
  });

  it("a bad wrapping version or truncated row is corrupted-marked integrity", () => {
    const tampered = [
      storedOf((sealed) => {
        sealed[0] = 0x01;
        return sealed;
      }),
      storedOf((sealed) => sealed.subarray(0, 40)),
    ];
    const errors = tampered.map((stored) => unwrapError(hexToBytes(vector.kek), stored));
    for (const error of errors) {
      expect(error?.code).toBe("integrity");
      expect(error?.corrupted).toBe(true);
    }
  });

  it("a binding computed under another DEK fails factorBindingOk", () => {
    const wrongDek = Secret.take(new Uint8Array(32).fill(1));
    expect(factorBindingOk(wrongDek, intact())).toBe(false);
    wrongDek.wipe();
  });
});
