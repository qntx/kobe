import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";

import { KobeError } from "../core/error.ts";
import { Secp256k1Signer } from "../core/secp256k1.ts";
import type { SecretKey } from "../core/secret.ts";
import type { RecoverableSignature } from "../core/signature.ts";
import { addressFromUncompressed, parseAddress } from "./address.ts";
import { hashTypedDataJson } from "./eip712.ts";
import {
  concatEncoded,
  decodeList,
  encodeBytes,
  encodeList,
  encodeSignedLegacyTransaction,
  encodeSignedTypedTransaction,
  encodeUint,
  isRlpZero,
  itemPayload,
  listItems,
} from "./rlp.ts";

const TX_TYPE_EIP2930 = 0x01;
const TX_TYPE_EIP1559 = 0x02;
const TX_TYPE_EIP7702 = 0x04;
const MAGIC_7702 = 0x05;
const U64_MAX = 2n ** 64n - 1n;

/**
 * EVM signer over a secp256k1 secret.
 *
 * The EVM owns the hash for every operation — the caller hands over the raw transaction, message,
 * typed data or authorization and the signer hashes the full payload before producing a recoverable
 * signature. The secret lives in the wrapped {@link Secp256k1Signer}; this class keeps no second
 * copy.
 */
export class EvmSigner {
  readonly #inner: Secp256k1Signer;

  private constructor(inner: Secp256k1Signer) {
    this.#inner = inner;
  }

  /**
   * Create from a 32-byte secret (copied).
   *
   * @throws KobeError crypto if the scalar is zero or ≥ the curve order; input if `secret` is
   *   disposed
   */
  static fromSecretKey(secret: SecretKey): EvmSigner {
    return new EvmSigner(Secp256k1Signer.fromSecretKey(secret));
  }

  /** 33-byte SEC1 compressed public key (fresh copy). */
  publicKey(): Uint8Array {
    return this.#inner.compressedPublicKey();
  }

  /** EIP-55 checksummed address derived from the public key. */
  address(): string {
    return addressFromUncompressed(this.#inner.uncompressedPublicKey());
  }

  /**
   * Hash and sign an unsigned RLP transaction envelope. See {@link transactionHash} for the envelope
   * rules.
   *
   * @throws KobeError input on a malformed or unsupported envelope, or if disposed
   */
  signTransaction(unsigned: Uint8Array): RecoverableSignature {
    return this.#inner.signRecoverable(transactionHash(unsigned));
  }

  /**
   * Sign an EIP-191 personal message (`\x19Ethereum Signed Message:` prefix).
   *
   * @throws KobeError input if disposed
   */
  signPersonalMessage(message: Uint8Array): RecoverableSignature {
    return this.#inner.signRecoverable(personalMessageHash(message));
  }

  /**
   * Hash and sign an EIP-712 typed-data JSON document (v4).
   *
   * @throws KobeError input on malformed JSON or invalid typed data, or if disposed
   */
  signTypedData(typedDataJson: string): RecoverableSignature {
    return this.#inner.signRecoverable(typedDataHash(typedDataJson));
  }

  /**
   * Sign an EIP-7702 authorization tuple `(chainId, address, nonce)`.
   *
   * @throws KobeError input on a malformed address or out-of-range `chainId`/`nonce`, or if
   *   disposed
   */
  signAuthorization(chainId: bigint, address: string, nonce: bigint): RecoverableSignature {
    return this.#inner.signRecoverable(authorizationHash(chainId, address, nonce));
  }

  dispose(): void {
    this.#inner.dispose();
  }
}

/**
 * Hash of an unsigned transaction envelope — `keccak256` of the bytes as given — after validating
 * the envelope shape.
 *
 * Envelope rules (all failures are KobeError input):
 *
 * - Typed: first byte `0x01` (EIP-2930), `0x02` (EIP-1559) or `0x04` (EIP-7702) followed by one
 *   well-formed RLP list spanning the rest of the bytes exactly. `0x03` (EIP-4844) and any other
 *   type byte are rejected.
 * - Legacy: a bare RLP list with exactly 9 items — the EIP-155 unsigned form `[nonce, gasPrice,
 *   gasLimit, to, value, data, chainId, 0, 0]` — whose last two items are empty and whose `chainId`
 *   fits in 8 bytes. A 6-item pre-EIP-155 list is rejected.
 *
 * @throws KobeError input on a malformed or unsupported envelope
 */
export function transactionHash(unsigned: Uint8Array): Uint8Array {
  validateEnvelope(unsigned);
  return keccak_256(unsigned);
}

/** `keccak256("\x19Ethereum Signed Message:\n" ‖ len ‖ message)`. */
export function personalMessageHash(message: Uint8Array): Uint8Array {
  const prefix = new TextEncoder().encode(`\u0019Ethereum Signed Message:\n${message.length}`);
  const buf = new Uint8Array(prefix.length + message.length);
  buf.set(prefix, 0);
  buf.set(message, prefix.length);
  return keccak_256(buf);
}

/**
 * EIP-712 v4 hash of a typed-data JSON document.
 *
 * @throws KobeError input on malformed JSON or invalid typed data
 */
export function typedDataHash(typedDataJson: string): Uint8Array {
  return hashTypedDataJson(typedDataJson);
}

/**
 * EIP-7702 authorization hash: `keccak256(0x05 ‖ rlp([chainId, address, nonce]))`.
 *
 * @throws KobeError input on a malformed address or `chainId`/`nonce` outside `u64`
 */
export function authorizationHash(chainId: bigint, address: string, nonce: bigint): Uint8Array {
  const addr = parseAddress(address);
  return authorizationHashBytes(chainId, addr, nonce);
}

/**
 * Encode a fully signed transaction envelope from its unsigned form.
 *
 * - Typed (`0x01`/`0x02`/`0x04`): `type ‖ rlp([…fields, yParity, r, s])` where `yParity` is the raw
 *   recovery bit (`0` encodes as `0x80`).
 * - Legacy: `rlp([nonce, gasPrice, gasLimit, to, value, data, v, r, s])` with `v = chainId * 2 + 35 +
 *   recovery` (EIP-155).
 *
 * `r` and `s` are encoded with leading zeros stripped.
 *
 * @throws KobeError input on a malformed envelope or a 6-item legacy list
 */
export function encodeSignedTransaction(
  unsigned: Uint8Array,
  signature: RecoverableSignature,
): Uint8Array {
  if (signature.signature.length !== 64) {
    throw new KobeError("input", "signature must be 64 bytes (r ‖ s)");
  }
  const first = unsigned.at(0);
  if (first === undefined) {
    throw new KobeError("input", "empty transaction");
  }
  if (first === TX_TYPE_EIP2930 || first === TX_TYPE_EIP1559 || first === TX_TYPE_EIP7702) {
    return encodeSignedTypedTransaction(unsigned, signature);
  }
  if (first >= 0xc0) {
    const items = listItems(decodeList(unsigned));
    const chainId = validateLegacyItems(items);
    return encodeSignedLegacyTransaction(unsigned, signature, chainId);
  }
  throw new KobeError("input", "unsupported transaction type");
}

/** 65-byte wire form `r ‖ s ‖ (27 + recovery)` used by EIP-191 / EIP-712. */
export function encodeSignature(signature: RecoverableSignature): Uint8Array {
  if (signature.signature.length !== 64) {
    throw new KobeError("input", "signature must be 64 bytes (r ‖ s)");
  }
  const out = new Uint8Array(65);
  out.set(signature.signature, 0);
  out[64] = 27 + signature.recovery;
  return out;
}

/**
 * Recover the EIP-55 checksummed signer address from a digest and a recoverable signature.
 *
 * @throws KobeError input on a malformed signature or failed recovery
 */
export function recoverAddress(digest: Uint8Array, signature: RecoverableSignature): string {
  if (digest.length !== 32) {
    throw new KobeError("input", "digest must be 32 bytes");
  }
  if (signature.signature.length !== 64) {
    throw new KobeError("input", "signature must be 64 bytes (r ‖ s)");
  }
  if (signature.recovery !== 0 && signature.recovery !== 1) {
    throw new KobeError("input", "recovery must be 0 or 1");
  }
  try {
    const point = secp256k1.Signature.fromBytes(signature.signature, "compact")
      .addRecoveryBit(signature.recovery)
      .recoverPublicKey(digest);
    return addressFromUncompressed(point.toBytes(false));
  } catch (error) {
    if (error instanceof KobeError) {
      throw error;
    }
    throw new KobeError(
      "input",
      error instanceof Error ? error.message : "signature recovery failed",
      { cause: error },
    );
  }
}

function validateEnvelope(unsigned: Uint8Array): void {
  const first = unsigned.at(0);
  if (first === undefined) {
    throw new KobeError("input", "empty transaction");
  }
  if (first === TX_TYPE_EIP2930 || first === TX_TYPE_EIP1559 || first === TX_TYPE_EIP7702) {
    decodeList(unsigned.subarray(1));
    return;
  }
  if (first >= 0xc0) {
    validateLegacyItems(listItems(decodeList(unsigned)));
    return;
  }
  throw new KobeError("input", "unsupported transaction type");
}

/** Validate the 9-item EIP-155 unsigned form and return its chain id. */
function validateLegacyItems(items: Uint8Array[]): bigint {
  if (items.length === 6) {
    throw new KobeError("input", "legacy transaction must carry an EIP-155 chain id");
  }
  if (items.length !== 9) {
    throw new KobeError("input", "legacy transaction must contain 9 fields");
  }
  const chainItem = items.at(6);
  const padR = items.at(7);
  const padS = items.at(8);
  if (padR === undefined || padS === undefined || chainItem === undefined) {
    throw new KobeError("input", "legacy transaction must contain 9 fields");
  }
  if (!isRlpZero(padR) || !isRlpZero(padS)) {
    throw new KobeError("input", "legacy EIP-155 placeholder fields must be empty");
  }
  const chainId = itemPayload(chainItem);
  if (chainId.length > 8) {
    throw new KobeError("input", "legacy chain id exceeds u64");
  }
  let id = 0n;
  for (const b of chainId) {
    id = id * 256n + BigInt(b);
  }
  return id;
}

function authorizationHashBytes(chainId: bigint, address: Uint8Array, nonce: bigint): Uint8Array {
  if (chainId < 0n || chainId > U64_MAX) {
    throw new KobeError("input", "chainId must fit in u64");
  }
  if (nonce < 0n || nonce > U64_MAX) {
    throw new KobeError("input", "nonce must fit in u64");
  }
  const items = concatEncoded([encodeUint(chainId), encodeBytes(address), encodeUint(nonce)]);
  const list = encodeList(items);
  const buf = new Uint8Array(1 + list.length);
  buf[0] = MAGIC_7702;
  buf.set(list, 1);
  return keccak_256(buf);
}
