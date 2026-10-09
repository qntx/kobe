// oxlint-disable no-bitwise -- seeded PRNG arithmetic and byte-tamper testing
import { bytesToHex } from "@noble/hashes/utils.js";
import { describe, expect, test } from "vite-plus/test";

import { KobeError } from "../../src/core/error.ts";
import { open, seal } from "../../src/vault/index.ts";

/** SplitMix64-seeded deterministic RNG for tests (not for production). */
class SplitMix64 {
  #state: bigint;

  constructor(seed: bigint) {
    this.#state = seed;
  }

  next(): bigint {
    this.#state = (this.#state + 0x9e3779b97f4a7c15n) & 0xffffffffffffffffn;
    let z = this.#state;
    z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & 0xffffffffffffffffn;
    z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & 0xffffffffffffffffn;
    return z ^ (z >> 31n);
  }

  bytes(n: number): Uint8Array {
    const out = new Uint8Array(n);
    let i = 0;
    while (i < n) {
      let z = this.next();
      for (let b = 0; b < 8 && i < n; b += 1) {
        out[i] = Number(z & 0xffn);
        z >>= 8n;
        i += 1;
      }
    }
    return out;
  }
}

/** Copy `bytes` with the byte at `index` flipped by XOR 0x01. */
function flipByte(bytes: Uint8Array, index: number): Uint8Array {
  const out = new Uint8Array(bytes);
  out[index] = (out[index] ?? 0) ^ 0x01;
  return out;
}

/** Run `f`, returning the thrown `KobeError.code`; sentinels keep assertions unconditional. */
function codeOf(f: () => unknown): string {
  try {
    f();
    return "<no error thrown>";
  } catch (error) {
    return error instanceof KobeError ? error.code : "<non-KobeError thrown>";
  }
}

describe("vault envelope properties", () => {
  test("random key/plaintext/context round-trips", () => {
    const rng = new SplitMix64(0x5eedn);
    for (let i = 0; i < 64; i += 1) {
      const key = rng.bytes(32);
      const plaintext = rng.bytes(Number(rng.next() % 129n));
      const context = `ctx/${i}/${rng.next().toString(16)}`;
      const sealed = seal(key, plaintext, context, (out) => out.set(rng.bytes(12)));
      expect(bytesToHex(open(key, sealed, context))).toBe(bytesToHex(plaintext));
    }
  });

  test("flipping any single byte fails", () => {
    const rng = new SplitMix64(0xf11fn);
    const key = rng.bytes(32);
    const plaintext = rng.bytes(48);
    const context = "kobe/test/v1/test/data";
    const sealed = seal(key, plaintext, context, (out) => out.set(rng.bytes(12)));

    expect(codeOf(() => open(key, flipByte(sealed, 0), context))).toBe("version");
    for (let i = 1; i < sealed.length; i += 1) {
      expect(
        codeOf(() => open(key, flipByte(sealed, i), context)),
        `byte ${i}`,
      ).toBe("decrypt");
    }
  });

  test("context mismatch fails with decrypt", () => {
    const rng = new SplitMix64(0xc0ffeen);
    const key = rng.bytes(32);
    const sealed = seal(key, rng.bytes(24), "kobe/test/v1/a/data", (out) => out.set(rng.bytes(12)));
    expect(codeOf(() => open(key, sealed, "kobe/test/v1/b/data"))).toBe("decrypt");
  });
});
