import { bytesToHex } from "../../crypto/hex.ts";
import { hash256 } from "../../crypto/index.ts";
import type { DerivedAccount } from "../../hd/account.ts";
import {
  secp256k1SignerFromSecret,
  signerFromSecret,
  type SecretKey32,
  type Secp256k1Signer,
  type SignOutput,
  withVOffset,
} from "../../sign/index.ts";
import { encodeSparkAddress, type SparkNetwork } from "./address.ts";

/** BIP-137 compressed P2PKH header offset (v = 31 | 32). */
const BIP137_P2PKH_COMPRESSED = 31;

function compactSize(len: number): Uint8Array {
  if (len < 253) return Uint8Array.of(len);
  if (len <= 0xffff) return Uint8Array.of(0xfd, len & 0xff, (len >> 8) & 0xff);
  return Uint8Array.of(0xfe, len & 0xff, (len >> 8) & 0xff, (len >> 16) & 0xff, (len >> 24) & 0xff);
}

/** double_SHA256("\x18Bitcoin Signed Message:\n" || CompactSize(len) || message) */
export function sparkMessageDigest(message: Uint8Array): Uint8Array {
  const prefix = new TextEncoder().encode("\x18Bitcoin Signed Message:\n");
  const len = compactSize(message.length);
  const data = new Uint8Array(prefix.length + len.length + message.length);
  data.set(prefix, 0);
  data.set(len, prefix.length);
  data.set(message, prefix.length + len.length);
  return hash256(data);
}

/**
 * Spark signer. Address encoding is kobe-spark proto-wrap Bech32m
 * (not the hash160 form in signer-spark). Framing is BIP-137 + double-SHA256.
 */
export interface SparkSigner {
  address(): string;
  publicKeyBytes(): Uint8Array;
  publicKeyHex(): string;
  signDigest(digest: Uint8Array): SignOutput;
  signMessage(message: Uint8Array): SignOutput;
  signTransaction(sighashPreimage: Uint8Array): SignOutput;
  verifyHash(hash: Uint8Array, signature: Uint8Array): boolean;
  dispose(): void;
  [Symbol.dispose](): void;
}

class SparkSignerImpl implements SparkSigner {
  readonly #inner: Secp256k1Signer;
  readonly #network: SparkNetwork;

  constructor(inner: Secp256k1Signer, network: SparkNetwork) {
    this.#inner = inner;
    this.#network = network;
  }

  address(): string {
    return encodeSparkAddress(this.#inner.compressedPublicKey(), this.#network);
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

  signMessage(message: Uint8Array): SignOutput {
    return withVOffset(
      this.#inner.signPrehashRecoverable(sparkMessageDigest(message)),
      BIP137_P2PKH_COMPRESSED,
    );
  }

  signTransaction(sighashPreimage: Uint8Array): SignOutput {
    return this.#inner.signPrehashRecoverable(hash256(sighashPreimage));
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

export function sparkSignerFromSecretKey(
  key: SecretKey32,
  network: SparkNetwork = "mainnet",
): SparkSigner {
  return new SparkSignerImpl(secp256k1SignerFromSecret(key), network);
}

export const {
  fromBytes: sparkSignerFromBytes,
  fromHex: sparkSignerFromHex,
  fromDerived: sparkSignerFromDerived,
} = signerFromSecret(sparkSignerFromSecretKey);

export function createSparkSigner(
  account: DerivedAccount,
  network: SparkNetwork = "mainnet",
): SparkSigner {
  return sparkSignerFromDerived(account, network);
}

export const SparkSigner = {
  fromSecretKey: sparkSignerFromSecretKey,
  fromBytes: sparkSignerFromBytes,
  fromHex: sparkSignerFromHex,
  fromDerived: sparkSignerFromDerived,
};
