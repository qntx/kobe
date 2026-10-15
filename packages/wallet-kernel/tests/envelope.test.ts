import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vite-plus/test";

import { open, seal } from "../src/vault/envelope.ts";
import { fixedRandom, kernelError, loadVectors } from "./helpers.ts";

type EnvelopeVector = {
  key: string;
  nonce: string;
  context: string;
  header: string;
  plaintext: string;
  sealed: string;
};
const { vectors } = loadVectors("envelope.json") as { vectors: EnvelopeVector[] };

function parts(vector: EnvelopeVector) {
  return {
    key: hexToBytes(vector.key),
    nonce: hexToBytes(vector.nonce),
    plaintext: hexToBytes(vector.plaintext),
    sealed: hexToBytes(vector.sealed),
  };
}

describe("envelope vectors", () => {
  it.each(vectors)("seals and opens $context", (vector) => {
    const { key, nonce, plaintext, sealed } = parts(vector);
    expect(
      bytesToHex(seal(key, plaintext, vector.context, vector.header, fixedRandom(nonce))),
    ).toBe(vector.sealed);
    expect(bytesToHex(open(key, sealed, vector.context, vector.header))).toBe(vector.plaintext);
  });
});

describe("open rejects", () => {
  const vector = vectors[0]!;
  const { key, plaintext, sealed } = parts(vector);
  const { context, header } = vector;

  it("flipped ciphertext byte", () => {
    const tampered = Uint8Array.from(sealed);
    tampered[1 + 24] = 255 - tampered[1 + 24]!;
    expect(kernelError(() => open(key, tampered, context, header))).toBe("integrity");
  });

  it("flipped tag byte", () => {
    const tampered = Uint8Array.from(sealed);
    const last = tampered.length - 1;
    tampered[last] = 255 - tampered[last]!;
    expect(kernelError(() => open(key, tampered, context, header))).toBe("integrity");
  });

  it("different context", () => {
    expect(kernelError(() => open(key, sealed, `${context}x`, header))).toBe("integrity");
  });

  it("different header", () => {
    const other = header.replace("generated", "nsec");
    expect(kernelError(() => open(key, sealed, context, other))).toBe("integrity");
  });

  it("wrong version byte", () => {
    const tampered = Uint8Array.from(sealed);
    tampered[0] = 0x02;
    expect(kernelError(() => open(key, tampered, context, header))).toBe("integrity");
  });

  it("truncated input", () => {
    expect(kernelError(() => open(key, sealed.slice(0, 20), context, header))).toBe("integrity");
    expect(kernelError(() => open(key, sealed.slice(0, -1), context, header))).toBe("integrity");
  });

  it("wrong key length", () => {
    expect(kernelError(() => open(key.slice(0, 31), sealed, context, header))).toBe("integrity");
    expect(
      kernelError(() =>
        seal(key.slice(0, 31), plaintext, context, header, fixedRandom(new Uint8Array(24))),
      ),
    ).toBe("invalid-input");
  });
});
