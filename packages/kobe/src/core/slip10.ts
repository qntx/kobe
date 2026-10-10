import { ed25519 } from "@noble/curves/ed25519.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";

import { copyBytes, wipeBytes } from "./bytes.ts";
import { KobeError } from "./error.ts";

const ED25519_SEED_KEY = new TextEncoder().encode("ed25519 seed");

/** SLIP-10 derived Ed25519 key material. */
export type DerivedEd25519Key = {
  /** Fresh 32-byte copy. @throws KobeError input if disposed */
  privateKeyBytes: () => Uint8Array;
  /** Footgun hex. @throws KobeError input if disposed */
  privateKeyHex: () => string;
  /** 32-byte Ed25519 public key. */
  publicKeyBytes: () => Uint8Array;
  publicKeyHex: () => string;
  dispose: () => void;
  toString: () => string;
};

class DerivedEd25519KeyImpl implements DerivedEd25519Key {
  #sk: Uint8Array | undefined;
  #chainCode: Uint8Array | undefined;
  readonly #pk: Uint8Array;
  #disposed = false;

  constructor(sk: Uint8Array, chainCode: Uint8Array) {
    this.#sk = sk;
    this.#chainCode = chainCode;
    this.#pk = ed25519.getPublicKey(sk);
  }

  #live(): Uint8Array {
    const sk = this.#sk;
    if (this.#disposed || !sk) {
      throw new KobeError("input", "disposed");
    }
    return sk;
  }

  privateKeyBytes(): Uint8Array {
    return copyBytes(this.#live());
  }

  privateKeyHex(): string {
    return bytesToHex(this.privateKeyBytes());
  }

  publicKeyBytes(): Uint8Array {
    return copyBytes(this.#pk);
  }

  publicKeyHex(): string {
    return bytesToHex(this.#pk);
  }

  dispose(): void {
    if (this.#disposed) {
      return;
    }
    wipeBytes(this.#sk);
    wipeBytes(this.#chainCode);
    this.#sk = undefined;
    this.#chainCode = undefined;
    this.#disposed = true;
  }

  toString(): string {
    return "DerivedEd25519Key [REDACTED]";
  }
}

function masterFromSeed(seed: Uint8Array): { sk: Uint8Array; chainCode: Uint8Array } {
  const i = hmac(sha512, ED25519_SEED_KEY, seed);
  return { sk: i.subarray(0, 32), chainCode: i.subarray(32) };
}

function deriveHardened(
  sk: Uint8Array,
  chainCode: Uint8Array,
  index: number,
): { sk: Uint8Array; chainCode: Uint8Array } {
  const data = new Uint8Array(1 + 32 + 4);
  data.set(sk, 1); // data[0] stays 0x00 (private-key padding)
  new DataView(data.buffer).setUint32(33, index + 0x80_00_00_00);
  const i = hmac(sha512, chainCode, data);
  wipeBytes(data);
  return { sk: i.subarray(0, 32), chainCode: i.subarray(32) };
}

/**
 * Parse a SLIP-10 path: every non-`m` segment must be hardened (`'` or `h`).
 *
 * @throws KobeError path
 */
function parseSlip10HardenedPath(path: string): number[] {
  const trimmed = path.trim();
  if (trimmed === "m") {
    return [];
  }
  if (!trimmed.startsWith("m/")) {
    throw new KobeError("path", "slip10: path must start with 'm/' or be exactly 'm'");
  }
  const rest = trimmed.slice(2);
  if (rest.length === 0) {
    throw new KobeError("path", "slip10: empty path segments");
  }
  const indices: number[] = [];
  for (const part of rest.split("/")) {
    if (part.length === 0) {
      throw new KobeError("path", "slip10: empty path segment");
    }
    const hardened = part.endsWith("'") || part.endsWith("h");
    if (!hardened) {
      throw new KobeError(
        "path",
        `slip10: non-hardened segment '${part}' (Ed25519 requires hardened-only)`,
      );
    }
    const numStr = part.slice(0, -1);
    if (!/^\d+$/.test(numStr)) {
      throw new KobeError("path", `slip10: invalid segment '${part}'`);
    }
    const n = Number(numStr);
    if (!Number.isInteger(n) || n < 0 || n > 0x7f_ff_ff_ff) {
      throw new KobeError("path", `slip10: index out of range in '${part}'`);
    }
    indices.push(n);
  }
  return indices;
}

/**
 * Derive a SLIP-10 Ed25519 key at a hardened-only path from a BIP-39 seed.
 *
 * @throws KobeError path | crypto
 */
export function deriveEd25519FromSeed(seed: Uint8Array, path: string): DerivedEd25519Key {
  if (seed.length < 16) {
    throw new KobeError("crypto", "seed too short for SLIP-10");
  }
  const indices = parseSlip10HardenedPath(path);
  let { sk, chainCode } = masterFromSeed(seed);
  try {
    for (const index of indices) {
      const next = deriveHardened(sk, chainCode, index);
      wipeBytes(sk);
      wipeBytes(chainCode);
      ({ sk, chainCode } = next);
    }
    return new DerivedEd25519KeyImpl(copyBytes(sk), copyBytes(chainCode));
  } finally {
    wipeBytes(sk);
    wipeBytes(chainCode);
  }
}
