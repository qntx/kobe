import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "../../crypto/hex.ts";
import { hash256 } from "../../crypto/index.ts";
import { SignError } from "../../errors/sign.ts";
import { wipeBytes } from "../../secret/dispose.ts";
import {
  schnorrSignerFromSecret,
  secp256k1SignerFromSecret,
  secretKeyFromBytes,
  signerFromSecret,
  type SecretKey32,
  type Secp256k1Signer,
  type SignOutput,
  withVOffset,
} from "../../sign/index.ts";
import type { BtcAccount } from "./account.ts";
import { btcAddressFromCompressed } from "./address.ts";
import type { BtcAddressType, BtcNetwork } from "./types.ts";

export const BIP137_P2PKH_UNCOMPRESSED = 27;
export const BIP137_P2PKH_COMPRESSED = 31;
export const BIP137_SEGWIT_P2SH = 35;
export const BIP137_SEGWIT_BECH32 = 39;

export type BtcMessageAddressType =
  | "p2pkh-uncompressed"
  | "p2pkh-compressed"
  | "segwit-p2sh"
  | "segwit-bech32";

export function bip137Offset(type: BtcMessageAddressType): number {
  switch (type) {
    case "p2pkh-uncompressed":
      return BIP137_P2PKH_UNCOMPRESSED;
    case "p2pkh-compressed":
      return BIP137_P2PKH_COMPRESSED;
    case "segwit-p2sh":
      return BIP137_SEGWIT_P2SH;
    case "segwit-bech32":
      return BIP137_SEGWIT_BECH32;
  }
}

function compactSize(len: number): Uint8Array {
  if (len < 253) return Uint8Array.of(len);
  if (len <= 0xffff) {
    return Uint8Array.of(0xfd, len & 0xff, (len >> 8) & 0xff);
  }
  return Uint8Array.of(0xfe, len & 0xff, (len >> 8) & 0xff, (len >> 16) & 0xff, (len >> 24) & 0xff);
}

/** double_SHA256("\x18Bitcoin Signed Message:\n" || CompactSize(len) || message) */
export function bitcoinMessageDigest(message: Uint8Array): Uint8Array {
  const prefix = new TextEncoder().encode("\x18Bitcoin Signed Message:\n");
  const len = compactSize(message.length);
  const data = new Uint8Array(prefix.length + len.length + message.length);
  data.set(prefix, 0);
  data.set(len, prefix.length);
  data.set(message, prefix.length + len.length);
  return hash256(data);
}

function taggedHash(tag: string, data: Uint8Array): Uint8Array {
  const t = sha256(new TextEncoder().encode(tag));
  const h = sha256.create();
  h.update(t);
  h.update(t);
  h.update(data);
  return h.digest();
}

/** BIP-341 taproot_tweak_seckey with empty merkle (BIP-86 key-path). */
export function taprootTweakSecret(secret: Uint8Array): Uint8Array {
  if (secret.length !== 32) {
    throw new SignError("invalid_key", "taproot tweak requires 32-byte secret");
  }
  const Fn = secp256k1.Point.Fn;
  const d0 = Fn.fromBytes(secret);
  const P = secp256k1.Point.BASE.multiply(d0);
  const compressed = P.toBytes(true);
  const prefix = compressed[0];
  if (prefix !== 0x02 && prefix !== 0x03) {
    throw new SignError("invalid_key", "taproot tweak failed");
  }
  const d = prefix === 0x03 ? Fn.neg(d0) : d0;
  const tweakBytes = taggedHash("TapTweak", compressed.subarray(1));
  let t: ReturnType<typeof Fn.fromBytes>;
  try {
    t = Fn.fromBytes(tweakBytes);
  } catch (e) {
    throw new SignError("invalid_key", "taproot tweak out of range", { cause: e });
  }
  return Fn.toBytes(Fn.add(d, t));
}

export interface BtcSigner {
  /** @throws SignError invalid_key unless constructed from a derived account or `{ network, type }`. */
  address(): string;
  publicKeyBytes(): Uint8Array;
  publicKeyHex(): string;
  signDigest(digest: Uint8Array): SignOutput;
  /** ECDSA over an already-hashed 32-byte digest. DER. Does not hash256. */
  signDigestDer(digest: Uint8Array): SignOutput;
  /**
   * BIP-86 key-path Schnorr over a 32-byte TapSighash.
   * Tweaks the secret; does not hash256.
   */
  signTaprootKeyPath(digest: Uint8Array): SignOutput;
  signMessage(message: Uint8Array): SignOutput;
  signMessageWith(type: BtcMessageAddressType, message: Uint8Array): SignOutput;
  signTransaction(sighashPreimage: Uint8Array): SignOutput;
  verifyHash(hash: Uint8Array, signature: Uint8Array): boolean;
  dispose(): void;
  [Symbol.dispose](): void;
}

class BtcSignerImpl implements BtcSigner {
  readonly #inner: Secp256k1Signer;
  #sk: Uint8Array | undefined;
  readonly #address: string | undefined;

  constructor(inner: Secp256k1Signer, sk: Uint8Array, address: string | undefined) {
    this.#inner = inner;
    this.#sk = sk;
    this.#address = address;
  }

  #assertSk(): Uint8Array {
    if (this.#sk === undefined) throw new SignError("invalid_key", "disposed");
    return this.#sk;
  }

  address(): string {
    if (this.#address === undefined) {
      throw new SignError("invalid_key", "btc address requires network and type");
    }
    return this.#address;
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

  signDigestDer(digest: Uint8Array): SignOutput {
    return this.#inner.signPrehashDer(digest);
  }

  signTaprootKeyPath(digest: Uint8Array): SignOutput {
    if (digest.length !== 32) {
      throw new SignError("invalid_message", "digest must be 32 bytes");
    }
    const tweaked = taprootTweakSecret(this.#assertSk());
    try {
      using key = secretKeyFromBytes(tweaked);
      using schnorr = schnorrSignerFromSecret(key);
      return schnorr.signPrehash(digest);
    } finally {
      wipeBytes(tweaked);
    }
  }

  signMessage(message: Uint8Array): SignOutput {
    return this.signMessageWith("p2pkh-compressed", message);
  }

  signMessageWith(type: BtcMessageAddressType, message: Uint8Array): SignOutput {
    const digest = bitcoinMessageDigest(message);
    return withVOffset(this.#inner.signPrehashRecoverable(digest), bip137Offset(type));
  }

  signTransaction(sighashPreimage: Uint8Array): SignOutput {
    return this.#inner.signPrehashRecoverable(hash256(sighashPreimage));
  }

  verifyHash(hash: Uint8Array, signature: Uint8Array): boolean {
    if (signature[0] === 0x30) return this.#inner.verifyPrehashDer(hash, signature);
    const compact = signature.length === 65 ? signature.subarray(0, 64) : signature;
    return this.#inner.verifyPrehash(hash, compact);
  }

  dispose(): void {
    wipeBytes(this.#sk);
    this.#sk = undefined;
    this.#inner.dispose();
  }

  [Symbol.dispose](): void {
    this.dispose();
  }
}

export type BtcSignerAddressSpec = {
  network: BtcNetwork;
  type: BtcAddressType;
};

function btcSignerWithAddress(key: SecretKey32, address: string | undefined): BtcSigner {
  return new BtcSignerImpl(secp256k1SignerFromSecret(key), key.toBytes(), address);
}

export function btcSignerFromSecretKey(key: SecretKey32, spec?: BtcSignerAddressSpec): BtcSigner {
  const inner = secp256k1SignerFromSecret(key);
  const address =
    spec === undefined
      ? undefined
      : btcAddressFromCompressed(inner.compressedPublicKey(), spec.network, spec.type);
  return new BtcSignerImpl(inner, key.toBytes(), address);
}

export const { fromBytes: btcSignerFromBytes, fromHex: btcSignerFromHex } =
  signerFromSecret(btcSignerFromSecretKey);

const btcFromCaptured = signerFromSecret(btcSignerWithAddress);

export function btcSignerFromDerived(account: BtcAccount): BtcSigner {
  return btcFromCaptured.fromDerived(account, account.address);
}

export function createBtcSigner(account: BtcAccount): BtcSigner {
  return btcSignerFromDerived(account);
}

export const BtcSigner = {
  fromSecretKey: btcSignerFromSecretKey,
  fromBytes: btcSignerFromBytes,
  fromHex: btcSignerFromHex,
  fromDerived: btcSignerFromDerived,
};
