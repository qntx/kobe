import { bytesToHex } from "../crypto/hex.ts";
import { hmacSha512 } from "../crypto/index.ts";
import { ed25519PublicKey } from "../ecc/ed25519.ts";
import { DeriveError } from "../errors/derive.ts";
import { copyBytes, wipeBytes } from "../secret/dispose.ts";

const ED25519_SEED_KEY = new TextEncoder().encode("ed25519 seed");

/** SLIP-10 derived Ed25519 key material. */
export interface DerivedEd25519Key {
  privateKeyBytes(): Uint8Array;
  privateKeyHex(): string;
  publicKeyBytes(): Uint8Array;
  publicKeyHex(): string;
  dispose(): void;
  [Symbol.dispose](): void;
  toString(): string;
}

class DerivedEd25519KeyImpl implements DerivedEd25519Key {
  #sk: Uint8Array | undefined;
  #chainCode: Uint8Array | undefined;
  #pk: Uint8Array;
  #disposed = false;

  constructor(sk: Uint8Array, chainCode: Uint8Array) {
    this.#sk = sk;
    this.#chainCode = chainCode;
    this.#pk = ed25519PublicKey(sk);
  }

  #assertLive(): void {
    if (this.#disposed || !this.#sk) {
      throw new DeriveError("input", "disposed");
    }
  }

  privateKeyBytes(): Uint8Array {
    this.#assertLive();
    return copyBytes(this.#sk!);
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
    if (this.#disposed) return;
    wipeBytes(this.#sk);
    wipeBytes(this.#chainCode);
    this.#sk = undefined;
    this.#chainCode = undefined;
    this.#disposed = true;
  }

  [Symbol.dispose](): void {
    this.dispose();
  }

  toString(): string {
    return "DerivedEd25519Key [REDACTED]";
  }

  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return this.toString();
  }
}

function masterFromSeed(seed: Uint8Array): {
  sk: Uint8Array;
  chainCode: Uint8Array;
} {
  const I = hmacSha512(ED25519_SEED_KEY, seed);
  return { sk: I.subarray(0, 32), chainCode: I.subarray(32) };
}

function deriveHardened(
  sk: Uint8Array,
  chainCode: Uint8Array,
  index: number,
): { sk: Uint8Array; chainCode: Uint8Array } {
  const data = new Uint8Array(1 + 32 + 4);
  data[0] = 0x00;
  data.set(sk, 1);
  const hardened = (index | 0x8000_0000) >>> 0;
  data[33] = (hardened >>> 24) & 0xff;
  data[34] = (hardened >>> 16) & 0xff;
  data[35] = (hardened >>> 8) & 0xff;
  data[36] = hardened & 0xff;
  const I = hmacSha512(chainCode, data);
  wipeBytes(data);
  return { sk: I.subarray(0, 32), chainCode: I.subarray(32) };
}

/**
 * Parse SLIP-10 path: every non-m segment must be hardened (`'` or `h`).
 * @throws DeriveError path
 */
export function parseSlip10HardenedPath(path: string): number[] {
  const trimmed = path.trim();
  if (trimmed === "m") return [];
  if (!trimmed.startsWith("m/")) {
    throw new DeriveError("path", "slip10: path must start with 'm/' or be exactly 'm'");
  }
  const rest = trimmed.slice(2);
  if (rest.length === 0) {
    throw new DeriveError("path", "slip10: empty path segments");
  }
  const parts = rest.split("/");
  const indices: number[] = [];
  for (const part of parts) {
    if (part.length === 0) {
      throw new DeriveError("path", "slip10: empty path segment");
    }
    const hardened = part.endsWith("'") || part.endsWith("h") || part.endsWith("H");
    if (!hardened) {
      throw new DeriveError(
        "path",
        `slip10: non-hardened segment '${part}' (Ed25519 requires hardened-only)`,
      );
    }
    const numStr = part.slice(0, -1);
    if (!/^\d+$/.test(numStr)) {
      throw new DeriveError("path", `slip10: invalid segment '${part}'`);
    }
    const n = Number(numStr);
    if (!Number.isInteger(n) || n < 0 || n > 0x7fff_ffff) {
      throw new DeriveError("path", `slip10: index out of range in '${part}'`);
    }
    indices.push(n);
  }
  return indices;
}

/**
 * Derive SLIP-10 Ed25519 key at a hardened-only path from BIP-39 seed.
 * @throws DeriveError path | crypto
 */
export function deriveEd25519FromSeed(seed: Uint8Array, path: string): DerivedEd25519Key {
  if (seed.length < 16) {
    throw new DeriveError("crypto", "seed too short for SLIP-10");
  }
  const indices = parseSlip10HardenedPath(path);
  let { sk, chainCode } = masterFromSeed(seed);
  try {
    for (const index of indices) {
      const next = deriveHardened(sk, chainCode, index);
      wipeBytes(sk);
      wipeBytes(chainCode);
      sk = next.sk;
      chainCode = next.chainCode;
    }
    return new DerivedEd25519KeyImpl(copyBytes(sk), copyBytes(chainCode));
  } finally {
    wipeBytes(sk);
    wipeBytes(chainCode);
  }
}
