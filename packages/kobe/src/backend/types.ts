import type { Event, UnsignedEvent } from "@qntx/nostr/core";

import type { WordCount } from "../core/index.ts";

/**
 * Opaque reference to a wallet held by a backend. Positive integer, scoped to the backend instance
 * that issued it.
 */
export type WalletHandle = number & { readonly __kobe: "wallet" };

/**
 * Opaque reference to a Nostr secret key held by a backend. Positive integer, scoped to the backend
 * instance that issued it.
 */
export type NostrKeyHandle = number & { readonly __kobe: "nostr-key" };

/**
 * The kobe backend contract. The pure TypeScript backend (`createPureBackend`) implements it
 * in-process; the native backend (`kobe-ffi` + `@qntx/kobe-native`) implements it over FFI. Every
 * method is async except `release`/`revokeAll`, because the native backend runs heavy work off the
 * JS thread.
 *
 * All methods reject with `KobeError`; the `code` field carries the shared vocabulary. A released,
 * revoked, never-issued, or wrong-kind handle fails with code `handle`.
 */
export type KobeBackend = {
  /**
   * Generate a new wallet from CSPRNG entropy.
   *
   * @throws KobeError input — invalid word count
   */
  generateWallet: (wordCount: WordCount) => Promise<WalletHandle>;

  /**
   * Import an English BIP-39 mnemonic (no passphrase in P1a).
   *
   * @throws KobeError mnemonic | input — invalid phrase
   */
  importMnemonic: (phrase: string) => Promise<WalletHandle>;

  /**
   * Import a wallet from a 32-byte PRF output (passkey wallet v1).
   *
   * @throws KobeError input — `prfOutput` is not 32 bytes
   */
  importPasskeyPrf: (prfOutput: Uint8Array) => Promise<WalletHandle>;

  /**
   * Return the wallet's normalized mnemonic phrase.
   *
   * @throws KobeError handle — stale or wrong-kind handle
   */
  exportMnemonic: (wallet: WalletHandle) => Promise<string>;

  /**
   * Seal the wallet's mnemonic (UTF-8) under `dek` with vault envelope v1.
   *
   * @throws KobeError input | handle — bad DEK length, empty context, or stale handle
   */
  sealWallet: (wallet: WalletHandle, dek: Uint8Array, context: string) => Promise<Uint8Array>;

  /**
   * Open a sealed wallet blob and import the mnemonic.
   *
   * @throws KobeError input | version | decrypt | mnemonic | handle — vault and mnemonic errors
   *   keep their codes
   */
  openWallet: (sealed: Uint8Array, dek: Uint8Array, context: string) => Promise<WalletHandle>;

  /**
   * Derive the NIP-06 Nostr key at `account` (must be a u32).
   *
   * @throws KobeError input | handle — account out of range or stale handle
   */
  deriveNostrKey: (wallet: WalletHandle, account: number) => Promise<NostrKeyHandle>;

  /**
   * Import a raw 32-byte secp256k1 secret key.
   *
   * @throws KobeError input — not 32 bytes or not a valid scalar
   */
  importNostrKey: (secretKey: Uint8Array) => Promise<NostrKeyHandle>;

  /**
   * Return a fresh 32-byte copy of the secret key (e.g. to persist as `nostr-hot`).
   *
   * @throws KobeError handle — stale or wrong-kind handle
   */
  exportNostrKey: (key: NostrKeyHandle) => Promise<Uint8Array>;

  /**
   * Import a `nsec1…` bech32 secret key (NIP-19).
   *
   * @throws KobeError input — malformed, wrong prefix, or invalid scalar
   */
  importNsec: (nsec: string) => Promise<NostrKeyHandle>;

  /**
   * Export the secret key as a `nsec1…` bech32 string.
   *
   * @throws KobeError handle — stale or wrong-kind handle
   */
  exportNsec: (key: NostrKeyHandle) => Promise<string>;

  /**
   * The lowercase 64-hex x-only public key.
   *
   * @throws KobeError handle — stale or wrong-kind handle
   */
  nostrPublicKey: (key: NostrKeyHandle) => Promise<string>;

  /**
   * Fill `id`/`sig` on an unsigned event. `unsigned.pubkey` must equal the key's public key.
   *
   * @throws KobeError input | handle — pubkey mismatch, invalid event, or stale handle
   */
  signEvent: (key: NostrKeyHandle, unsigned: UnsignedEvent) => Promise<Event>;

  /**
   * NIP-44 encrypt `plaintext` for `peer` (64-hex public key). Conversation keys are cached per
   * (handle, lowercased peer).
   *
   * @throws KobeError input | handle — bad peer, invalid plaintext size, or stale handle
   */
  nip44Encrypt: (key: NostrKeyHandle, peer: string, plaintext: string) => Promise<string>;

  /**
   * NIP-44 decrypt a payload from `peer` (64-hex public key).
   *
   * @throws KobeError input | decrypt | handle — bad peer, corrupt payload, or stale handle
   */
  nip44Decrypt: (key: NostrKeyHandle, peer: string, payload: string) => Promise<string>;

  /**
   * NIP-04 encrypt `plaintext` for `peer` (64-hex public key).
   *
   * @throws KobeError input | handle — bad peer or stale handle
   */
  nip04Encrypt: (key: NostrKeyHandle, peer: string, plaintext: string) => Promise<string>;

  /**
   * NIP-04 decrypt a payload from `peer` (64-hex public key).
   *
   * @throws KobeError input | decrypt | handle — bad peer, corrupt payload, or stale handle
   */
  nip04Decrypt: (key: NostrKeyHandle, peer: string, ciphertext: string) => Promise<string>;

  /**
   * Release a handle: wipe its secrets (`Keys.secretKey.zeroize()`, conversation keys,
   * `Wallet.dispose()`). Idempotent; never throws. Releasing a wallet does not release keys derived
   * from it.
   */
  release: (handle: WalletHandle | NostrKeyHandle) => void;

  /** Release every handle this backend issued. Idempotent; never throws. */
  revokeAll: () => void;
};
