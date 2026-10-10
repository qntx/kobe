import { secp256k1 } from "@noble/curves/secp256k1.js";

import { bytesToHex } from "../../crypto/hex.ts";
import { keccak256 } from "../../crypto/index.ts";
import { SignError } from "../../errors/sign.ts";
import {
  EIP191_OFFSET,
  secp256k1SignerFromSecret,
  signerFromSecret,
  withVOffset,
} from "../../sign/index.ts";
import type { SecretKey32, Secp256k1Signer, SignerKit, SignOutput } from "../../sign/index.ts";
import { evmAddressFromUncompressed, parseEvmAddress } from "./address.ts";
import { hashTypedDataJson } from "./eip712.ts";
import {
  encodeAuthorization,
  encodeSignedLegacyTx,
  encodeSignedTypedTx,
  validateUnsignedEnvelope,
} from "./rlp.ts";

export type EvmSigner = {
  address(): string;
  publicKeyBytes(): Uint8Array;
  publicKeyHex(): string;
  signDigest(digest: Uint8Array): SignOutput;
  signMessage(message: Uint8Array): SignOutput;
  signTypedData(typedDataJson: string): SignOutput;
  signTransaction(unsignedTx: Uint8Array): SignOutput;
  signAuthorization(chainId: bigint, address: string, nonce: bigint): SignOutput;
  encodeSignedTransaction(unsignedTx: Uint8Array, signature: SignOutput): Uint8Array;
  verifyHash(hash: Uint8Array, signature: Uint8Array): boolean;
  dispose(): void;
  [Symbol.dispose](): void;
};

class EvmSignerImpl implements EvmSigner {
  readonly #inner: Secp256k1Signer;

  constructor(inner: Secp256k1Signer) {
    this.#inner = inner;
  }

  address(): string {
    return evmAddressFromUncompressed(this.#inner.uncompressedPublicKey());
  }

  publicKeyBytes(): Uint8Array {
    return this.#inner.compressedPublicKey();
  }

  publicKeyHex(): string {
    return bytesToHex(this.publicKeyBytes());
  }

  signDigest(digest: Uint8Array): SignOutput {
    return this.#inner.signDigest(digest);
  }

  /** EIP-191 personal message; the output `v` carries the +27 wire offset. */
  signMessage(message: Uint8Array): SignOutput {
    return withVOffset(
      this.#inner.signPrehashRecoverable(personalMessageHash(message)),
      EIP191_OFFSET,
    );
  }

  /** EIP-712 v4 typed-data JSON document; the output `v` carries the +27 wire offset. */
  signTypedData(typedDataJson: string): SignOutput {
    return withVOffset(
      this.#inner.signPrehashRecoverable(hashTypedDataJson(typedDataJson)),
      EIP191_OFFSET,
    );
  }

  /**
   * Unsigned RLP transaction envelope — legacy EIP-155 or typed `0x01`/`0x02`/`0x04`. The output
   * `v` is the raw recovery parity.
   *
   * @throws SignError invalid_transaction on a malformed or unsupported envelope
   */
  signTransaction(unsignedTx: Uint8Array): SignOutput {
    return this.#inner.signPrehashRecoverable(transactionHash(unsignedTx));
  }

  /**
   * EIP-7702 authorization tuple `(chainId, address, nonce)`; the output `v` is the raw recovery
   * parity (`yParity`).
   *
   * @throws SignError invalid_message on an out-of-range `chainId`/`nonce`; DeriveError on a
   *   malformed address
   */
  signAuthorization(chainId: bigint, address: string, nonce: bigint): SignOutput {
    return this.#inner.signPrehashRecoverable(authorizationHash(chainId, address, nonce));
  }

  /**
   * Signed envelope from an unsigned one: typed `type ‖ RLP([…fields, yParity, r, s])`; legacy
   * `RLP([…, v, r, s])` with `v = chainId * 2 + 35 + recovery` (EIP-155).
   *
   * @throws SignError invalid_transaction | invalid_signature
   */
  encodeSignedTransaction(unsignedTx: Uint8Array, signature: SignOutput): Uint8Array {
    if (signature.scheme !== "ecdsa_recoverable") {
      throw new SignError("invalid_signature", "expected Ecdsa signature output");
    }
    const envelope = validateUnsignedEnvelope(unsignedTx);
    const r = signature.signature.subarray(0, 32);
    const s = signature.signature.subarray(32, 64);
    if (envelope.kind === "typed") {
      return encodeSignedTypedTx(unsignedTx, signature.v, r, s);
    }
    return encodeSignedLegacyTx(unsignedTx, envelope.chainId, signature.v, r, s);
  }

  verifyHash(hash: Uint8Array, signature: Uint8Array): boolean {
    const compact = signature.length === 65 ? signature.subarray(0, 64) : signature;
    return this.#inner.verifyPrehash(hash, compact);
  }

  dispose(): void {
    this.#inner.dispose();
  }

  [Symbol.dispose](): void {
    this.dispose();
  }
}

/**
 * `keccak256` of an unsigned transaction envelope after validating its shape. See
 * {@link validateUnsignedEnvelope} for the envelope rules.
 */
export function transactionHash(unsignedTx: Uint8Array): Uint8Array {
  validateUnsignedEnvelope(unsignedTx);
  return keccak256(unsignedTx);
}

/** `keccak256("\x19Ethereum Signed Message:\n" ‖ len ‖ message)` (EIP-191). */
export function personalMessageHash(message: Uint8Array): Uint8Array {
  const prefix = new TextEncoder().encode(`\u0019Ethereum Signed Message:\n${message.length}`);
  const buf = new Uint8Array(prefix.length + message.length);
  buf.set(prefix, 0);
  buf.set(message, prefix.length);
  return keccak256(buf);
}

/**
 * EIP-7702 authorization hash: `keccak256(0x05 ‖ rlp([chainId, address, nonce]))`.
 *
 * @throws SignError invalid_message on `chainId`/`nonce` outside `u64`; DeriveError on a malformed
 *   address
 */
export function authorizationHash(chainId: bigint, address: string, nonce: bigint): Uint8Array {
  return keccak256(encodeAuthorization(chainId, parseEvmAddress(address), nonce));
}

/**
 * 65-byte wire form `r ‖ s ‖ v`, where `v` is the `v` field of an `ecdsa_recoverable`
 * {@link SignOutput} (EIP-191 / EIP-712 outputs carry the +27 offset already).
 *
 * @throws SignError invalid_signature on a non-recoverable output or a signature that is not 64
 *   bytes
 */
export function encodeSignature(signature: SignOutput): Uint8Array {
  if (signature.scheme !== "ecdsa_recoverable" || signature.signature.length !== 64) {
    throw new SignError("invalid_signature", "expected 64-byte recoverable Ecdsa signature output");
  }
  const out = new Uint8Array(65);
  out.set(signature.signature, 0);
  out[64] = signature.v;
  return out;
}

/**
 * Recover the EIP-55 checksummed signer address from a digest and a recoverable signature. `v` is
 * interpreted as the raw recovery bit; a `v ≥ 27` wire value is normalized first.
 *
 * @throws SignError invalid_message on a digest that is not 32 bytes; invalid_signature on a
 *   malformed signature or failed recovery
 */
export function recoverAddress(digest: Uint8Array, signature: SignOutput): string {
  if (digest.length !== 32) {
    throw new SignError("invalid_message", "digest must be 32 bytes");
  }
  if (signature.scheme !== "ecdsa_recoverable" || signature.signature.length !== 64) {
    throw new SignError("invalid_signature", "expected 64-byte recoverable Ecdsa signature output");
  }
  const recovery = signature.v >= 27 ? signature.v - 27 : signature.v;
  if (recovery !== 0 && recovery !== 1) {
    throw new SignError("invalid_signature", "recovery must be 0 or 1");
  }
  try {
    const point = secp256k1.Signature.fromBytes(signature.signature, "compact")
      .addRecoveryBit(recovery)
      .recoverPublicKey(digest);
    return evmAddressFromUncompressed(point.toBytes(false));
  } catch (error) {
    if (error instanceof SignError) {
      throw error;
    }
    throw new SignError(
      "invalid_signature",
      error instanceof Error ? error.message : "signature recovery failed",
      { cause: error },
    );
  }
}

function evmSignerFromSecretKey(key: SecretKey32): EvmSigner {
  return new EvmSignerImpl(secp256k1SignerFromSecret(key));
}

export const EvmSigner: SignerKit<EvmSigner> = signerFromSecret(evmSignerFromSecretKey);
