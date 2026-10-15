import { Keys, KeysSigner } from "@qntx/nostr";
import type { Event, UnsignedEvent } from "@qntx/nostr";
import { decode as nip19Decode, nsecEncode } from "@qntx/nostr/nips/nip19";
import { decrypt as nip49Decrypt, encrypt as nip49Encrypt } from "@qntx/nostr/nips/nip49";
import { isGiftWrapKind, unwrap as nip59Unwrap } from "@qntx/nostr/nips/nip59";
import type { Rumor } from "@qntx/nostr/nips/nip59";
import type { UnwrapResult } from "@qntx/wallet/protocol";
import type { WalletErrorCode } from "@qntx/wallet/types";

import { KernelError } from "../errors.ts";
import type { KernelPlatform } from "../platform.ts";
import { decodeUtf8Secret, wipe } from "../secret/secret.ts";

/**
 * Signer pool: one KeysSigner per nostr-key record, keyed by public key. Built at unlock from the
 * authenticated record plaintexts; disposed at lock so secrets die with the session.
 */
export class SignerPool {
  private readonly signers = new Map<string, KeysSigner>();

  /** Takes ownership of `secretKey` and wipes it after the signer is constructed. */
  add(secretKey: Uint8Array): string {
    try {
      const signer = new KeysSigner(Keys.fromSecretKey(secretKey));
      const { publicKey } = signer.keys;
      this.signers.set(publicKey, signer);
      return publicKey;
    } finally {
      wipe(secretKey);
    }
  }

  get(publicKey: string): KeysSigner {
    const signer = this.signers.get(publicKey);
    if (signer === undefined) {
      throw new KernelError("not-found", "no such nostr key");
    }
    return signer;
  }

  remove(publicKey: string): void {
    const signer = this.signers.get(publicKey);
    if (signer !== undefined) {
      signer.dispose();
      this.signers.delete(publicKey);
    }
  }

  dispose(): void {
    for (const signer of this.signers.values()) {
      signer.dispose();
    }
    this.signers.clear();
  }
}

/** A fresh valid secp256k1 scalar from the platform RNG (retries on the ~2^-128 invalid draws). */
export function generateSecretKey(random: KernelPlatform["random"]): Uint8Array {
  for (;;) {
    const candidate = random(32);
    try {
      Keys.fromSecretKey(candidate);
      return candidate;
    } catch {
      wipe(candidate);
    }
  }
}

/** Decodes a UTF-8 `nsec1…` bech32 payload; the input bytes are wiped. */
export function secretKeyFromNsec(nsec: Uint8Array): Uint8Array {
  const text = decodeUtf8Secret(nsec); // wipes `nsec`
  try {
    const decoded = nip19Decode(text);
    if (decoded.type !== "nsec") {
      throw new KernelError("invalid-input", "expected an nsec bech32 string");
    }
    return new Uint8Array(decoded.data);
  } catch (error) {
    if (error instanceof KernelError) {
      throw error;
    }
    throw new KernelError("invalid-input", "invalid nsec");
  }
}

/**
 * Decrypts an `ncryptsec` with the UTF-8 `password` bytes (wiped after use). `maxLogN` 20 caps the
 * scrypt memory a crafted payload can demand.
 */
export async function secretKeyFromNcryptsec(
  ncryptsec: string,
  password: Uint8Array,
): Promise<Uint8Array> {
  const text = decodeUtf8Secret(password); // wipes `password`
  try {
    // nip49 derives with NFKC internally; the salt nonce comes from the library's own RNG.
    return await nip49Decrypt(ncryptsec, text, { maxLogN: 20 });
  } catch {
    throw new KernelError("invalid-input", "invalid ncryptsec or wrong password");
  }
}

export function nsecFromSecretKey(secretKey: Uint8Array): Uint8Array {
  return new TextEncoder().encode(nsecEncode(secretKey));
}

/** Export `ncryptsec` at logN 16; `ksb` is the NIP-49 key security byte chosen by the caller. */
export async function ncryptsecFromSecretKey(
  secretKey: Uint8Array,
  password: Uint8Array,
  ksb: 0x01 | 0x02,
): Promise<Uint8Array> {
  const text = decodeUtf8Secret(password); // wipes `password`
  // salt and nonce come from the library's RNG (noble randomBytes); not injectable in 0.13.
  const encoded = await nip49Encrypt(secretKey, text, { logn: 16, ksb });
  return new TextEncoder().encode(encoded);
}

/** Validates the host-supplied pubkey hint and signs. Everything else is pre-validated. */
export async function signEvent(
  pool: SignerPool,
  publicKey: string,
  event: {
    readonly kind: number;
    readonly created_at: number;
    readonly tags: ReadonlyArray<ReadonlyArray<string>>;
    readonly content: string;
    readonly pubkey?: string;
  },
): Promise<Event> {
  if (event.pubkey !== undefined && event.pubkey !== publicKey) {
    throw new KernelError("invalid-input", "event pubkey does not match the selected key");
  }
  const unsigned: UnsignedEvent = {
    pubkey: publicKey,
    kind: event.kind,
    created_at: event.created_at,
    tags: event.tags,
    content: event.content,
  };
  return pool.get(publicKey).signEvent(unsigned);
}

/** Per-item unwrap: malformed gift wraps are isolated failures, never aborts. */
export async function unwrapGiftWrap(
  pool: SignerPool,
  publicKey: string,
  event: Event,
): Promise<UnwrapResult> {
  if (!isGiftWrapKind(event.kind)) {
    return { err: "invalid-input" };
  }
  try {
    const rumor: Rumor = await nip59Unwrap(pool.get(publicKey), event);
    return { ok: rumor };
  } catch (error) {
    const err: WalletErrorCode = error instanceof KernelError ? error.code : "integrity";
    return { err };
  }
}
