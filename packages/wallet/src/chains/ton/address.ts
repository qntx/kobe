import { base64urlnopad } from "@scure/base";
import { sha256Bytes } from "../../crypto/index.ts";
import { DeriveError } from "../../errors/derive.ts";

/** Wallet v5r1 code cell hash (SHA-256 of the cell representation). */
export const WALLET_V5R1_CODE_HASH = Uint8Array.of(
  0x20,
  0x83,
  0x4b,
  0x7b,
  0x72,
  0xb1,
  0x12,
  0x14,
  0x7e,
  0x1b,
  0x2f,
  0xb4,
  0x57,
  0xb8,
  0x4e,
  0x74,
  0xd1,
  0xa3,
  0x0f,
  0x04,
  0xf7,
  0x37,
  0xd4,
  0xf6,
  0x2a,
  0x66,
  0x8e,
  0x95,
  0x52,
  0xd2,
  0xb7,
  0x2f,
);

/** Wallet v5r1 code cell depth. */
export const WALLET_V5R1_CODE_DEPTH = 6;

/** TON mainnet global id (`-239`). */
const NETWORK_GLOBAL_ID_MAINNET = -239;

/** TON testnet global id (`-3`). */
const NETWORK_GLOBAL_ID_TESTNET = -3;

/**
 * User-friendly TON address format (workchain / bounce / network).
 * Does not affect SLIP-10 key derivation.
 */
export interface TonAddressFormat {
  readonly workchain: number;
  readonly bounceable: boolean;
  readonly testnet: boolean;
}

/** Mainnet, workchain 0, non-bounceable (`UQ…`). */
export const TON_ADDRESS_DEFAULT: TonAddressFormat = {
  workchain: 0,
  bounceable: false,
  testnet: false,
};

/** Mainnet, workchain 0, bounceable (`EQ…`). */
export const TON_ADDRESS_BOUNCEABLE: TonAddressFormat = {
  workchain: 0,
  bounceable: true,
  testnet: false,
};

/** Testnet, workchain 0, non-bounceable (`0Q…`). */
export const TON_ADDRESS_TESTNET: TonAddressFormat = {
  workchain: 0,
  bounceable: false,
  testnet: true,
};

/** @throws DeriveError input if workchain is not an i8 integer */
export function createTonAddressFormat(
  workchain: number,
  bounceable: boolean,
  testnet: boolean,
): TonAddressFormat {
  assertI8(workchain);
  return { workchain, bounceable, testnet };
}

function assertI8(workchain: number): number {
  if (!Number.isInteger(workchain) || workchain < -128 || workchain > 127) {
    throw new DeriveError("input", "ton workchain must be an i8 integer");
  }
  return workchain;
}

function workchainByte(workchain: number): number {
  return assertI8(workchain) & 0xff;
}

/**
 * v5r1 client context:
 * `[is_client:1 = 1][workchain:i8][wallet_version:u8 = 0][subwallet:u15 = 0]`.
 */
function encodeClientContext(workchain: number): number {
  const bits = (0x8000_0000 | (workchainByte(workchain) << 23)) >>> 0;
  return bits | 0;
}

/**
 * `walletId = networkGlobalId ^ clientContext`.
 * Matches `@ton/core` `WalletV5R1WalletId`.
 */
export function tonWalletId(format: TonAddressFormat): number {
  const globalId = format.testnet ? NETWORK_GLOBAL_ID_TESTNET : NETWORK_GLOBAL_ID_MAINNET;
  return (globalId ^ encodeClientContext(format.workchain)) | 0;
}

function i32ToBeBytes(v: number): Uint8Array {
  const u = v >>> 0;
  return Uint8Array.of((u >>> 24) & 0xff, (u >>> 16) & 0xff, (u >>> 8) & 0xff, u & 0xff);
}

/** Streaming MSB-first bit writer for TL-B cell serialization. */
class BitWriter {
  #bytes: number[] = [];
  /** Bits already written into the tail byte; always `0..7`. */
  #tailBits = 0;

  pushBit(bit: boolean): void {
    if (this.#tailBits === 0) {
      this.#bytes.push(bit ? 0x80 : 0);
    } else if (bit) {
      const last = this.#bytes.length - 1;
      this.#bytes[last] = (this.#bytes[last] ?? 0) | (1 << (7 - this.#tailBits));
    }
    this.#tailBits = (this.#tailBits + 1) & 0x07;
  }

  pushByte(b: number): void {
    const byte = b & 0xff;
    if (this.#tailBits === 0) {
      this.#bytes.push(byte);
      return;
    }
    const shift = this.#tailBits;
    const last = this.#bytes.length - 1;
    this.#bytes[last] = (this.#bytes[last] ?? 0) | (byte >> shift);
    this.#bytes.push((byte << (8 - shift)) & 0xff);
  }

  pushU32Be(v: number): void {
    for (const b of i32ToBeBytes(v >>> 0)) this.pushByte(b);
  }

  pushI32Be(v: number): void {
    for (const b of i32ToBeBytes(v | 0)) this.pushByte(b);
  }

  pushBytes(data: Uint8Array): void {
    for (const b of data) this.pushByte(b);
  }

  bitLen(): number {
    if (this.#tailBits === 0) return this.#bytes.length * 8;
    return (this.#bytes.length - 1) * 8 + this.#tailBits;
  }

  finalizeWithCompletionTag(): { bytes: Uint8Array; bitLen: number } {
    const bitLen = this.bitLen();
    if (this.#tailBits !== 0) {
      this.pushBit(true);
      while (this.#tailBits !== 0) this.pushBit(false);
    }
    return { bytes: Uint8Array.from(this.#bytes), bitLen };
  }
}

/**
 * Wallet v5r1 data cell hash.
 * Layout (322 bits): `is_sig_allowed(1) || seqno(32) || walletId(32) || pubkey(256) || extensions(1)`.
 */
export function dataCellHash(publicKey: Uint8Array, walletId: number): Uint8Array {
  if (publicKey.length !== 32) {
    throw new DeriveError(
      "crypto",
      `ton data cell: public key must be 32 bytes, got ${publicKey.length}`,
    );
  }
  const dataBits = 322;
  const d1 = 0;
  const d2 = 81;

  const writer = new BitWriter();
  writer.pushBit(true);
  writer.pushU32Be(0);
  writer.pushI32Be(walletId);
  writer.pushBytes(publicKey);
  writer.pushBit(false);

  const { bytes, bitLen } = writer.finalizeWithCompletionTag();
  if (bitLen !== dataBits) {
    throw new DeriveError("crypto", `ton data cell: expected ${dataBits} bits, got ${bitLen}`);
  }

  const repr = new Uint8Array(2 + bytes.length);
  repr[0] = d1;
  repr[1] = d2;
  repr.set(bytes, 2);
  return sha256Bytes(repr);
}

/** `StateInit` cell hash (code + data refs). */
export function stateInitHash(
  codeHash: Uint8Array,
  codeDepth: number,
  dataHash: Uint8Array,
): Uint8Array {
  if (codeHash.length !== 32 || dataHash.length !== 32) {
    throw new DeriveError("crypto", "ton state init: hashes must be 32 bytes");
  }
  const d1 = 2;
  const d2 = 1;
  const repr = new Uint8Array(3 + 4 + 64);
  repr[0] = d1;
  repr[1] = d2;
  repr[2] = 0x34;
  repr[3] = (codeDepth >>> 8) & 0xff;
  repr[4] = codeDepth & 0xff;
  repr[5] = 0;
  repr[6] = 0;
  repr.set(codeHash, 7);
  repr.set(dataHash, 39);
  return sha256Bytes(repr);
}

/** CRC-16/XMODEM (init 0, poly 0x1021). */
export function crc16Ccitt(data: Uint8Array): number {
  let crc = 0;
  for (const byte of data) {
    crc ^= byte << 8;
    for (let i = 0; i < 8; i++) {
      crc = (crc & 0x8000) !== 0 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
    }
  }
  return crc;
}

/** User-friendly TON address: tag || workchain || hash || CRC16, base64url no pad. */
export function encodeTonAddress(
  workchain: number,
  hash: Uint8Array,
  bounceable: boolean,
  testnet: boolean,
): string {
  if (hash.length !== 32) {
    throw new DeriveError(
      "address_encoding",
      `ton address hash must be 32 bytes, got ${hash.length}`,
    );
  }
  const base = bounceable ? 0x11 : 0x51;
  const tag = testnet ? base | 0x80 : base;
  const addr = new Uint8Array(36);
  addr[0] = tag;
  addr[1] = workchainByte(workchain);
  addr.set(hash, 2);
  const crc = crc16Ccitt(addr.subarray(0, 34));
  addr[34] = (crc >>> 8) & 0xff;
  addr[35] = crc & 0xff;
  try {
    return base64urlnopad.encode(addr);
  } catch (e) {
    throw new DeriveError(
      "address_encoding",
      e instanceof Error ? `ton address: ${e.message}` : "ton address encoding",
      { cause: e },
    );
  }
}

/** Wallet v5r1 user-friendly address from Ed25519 public key. */
export function tonAddressFromPublicKey(publicKey: Uint8Array, format: TonAddressFormat): string {
  const dataHash = dataCellHash(publicKey, tonWalletId(format));
  const stateHash = stateInitHash(WALLET_V5R1_CODE_HASH, WALLET_V5R1_CODE_DEPTH, dataHash);
  return encodeTonAddress(format.workchain, stateHash, format.bounceable, format.testnet);
}
