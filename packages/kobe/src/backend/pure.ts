/**
 * Pure TypeScript {@link KobeBackend}: wallets and Nostr keys live in-process, held behind integer
 * handles that can be released or revoked wholesale.
 */
import type { UnsignedEvent } from "@qntx/nostr/core";
import { Keys, signEvent } from "@qntx/nostr/core";
import * as nip04 from "@qntx/nostr/nips/nip04";
import * as nip19 from "@qntx/nostr/nips/nip19";
import * as nip44 from "@qntx/nostr/nips/nip44";

import { wipeBytes } from "../core/bytes.ts";
import { assertU32Index } from "../core/derive.ts";
import { KobeError } from "../core/error.ts";
import type { WordCount } from "../core/index.ts";
import { Wallet } from "../core/index.ts";
import { NostrDeriver } from "../nostr/index.ts";
import { open, passkeyWallet, seal } from "../vault/index.ts";
import type { KobeBackend, NostrKeyHandle, WalletHandle } from "./types.ts";

/** Options for {@link createPureBackend}. */
export type PureBackendOptions = {
  /**
   * Fill the provided buffer with CSPRNG bytes. Feeds `generateWallet` only (`sealWallet` and
   * NIP-44/04 use their libraries' CSPRNG). Without it, generation uses `@scure/bip39`'s CSPRNG
   * (`crypto.getRandomValues`).
   */
  rng?: (bytes: Uint8Array) => void;
};

type KeyRecord = {
  keys: Keys;
  /** Cached NIP-44 conversation keys, keyed by lowercased peer hex. */
  conversationKeys: Map<string, Uint8Array>;
};

const PEER_HEX = /^[0-9a-f]{64}$/;
const SECRET_KEY_LEN = 32;

function normalizePeer(peer: string): string {
  const lower = peer.toLowerCase();
  if (!PEER_HEX.test(lower)) {
    throw new KobeError("input", "backend: peer must be a 64-hex public key");
  }
  return lower;
}

function staleHandle(): KobeError {
  return new KobeError("handle", "backend: stale or wrong-kind handle");
}

/** Rethrow as `KobeError(code)` unless the failure already is a KobeError. */
function rethrow(code: "input" | "decrypt" | "crypto", message: string, error: unknown): never {
  if (error instanceof KobeError) {
    throw error;
  }
  throw new KobeError(code, message, { cause: error });
}

/**
 * Create the in-process backend. Handles are positive integers from a per-instance counter — there
 * is no global registry, so two backends never see each other's handles.
 */
export function createPureBackend(options: PureBackendOptions = {}): KobeBackend {
  const { rng } = options;
  let next = 1;
  const wallets = new Map<number, Wallet>();
  const keys = new Map<number, KeyRecord>();

  function issueWallet(wallet: Wallet): WalletHandle {
    const handle = next;
    next += 1;
    wallets.set(handle, wallet);
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- branding an issued handle
    return handle as WalletHandle;
  }

  function issueKey(record: KeyRecord): NostrKeyHandle {
    const handle = next;
    next += 1;
    keys.set(handle, record);
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- branding an issued handle
    return handle as NostrKeyHandle;
  }

  function requireWallet(handle: WalletHandle): Wallet {
    const wallet = wallets.get(handle);
    if (!wallet) {
      throw staleHandle();
    }
    return wallet;
  }

  function requireKey(handle: NostrKeyHandle): KeyRecord {
    const record = keys.get(handle);
    if (!record) {
      throw staleHandle();
    }
    return record;
  }

  function conversationKey(record: KeyRecord, peer: string): Uint8Array {
    const normalized = normalizePeer(peer);
    let conv = record.conversationKeys.get(normalized);
    if (!conv) {
      const secret = record.keys.secretKey.bytes;
      try {
        conv = nip44.getConversationKey(secret, normalized);
      } catch (error) {
        rethrow("input", "backend: invalid Nostr peer public key", error);
      } finally {
        wipeBytes(secret);
      }
      record.conversationKeys.set(normalized, conv);
    }
    return conv;
  }

  function importSecret(secret: Uint8Array): NostrKeyHandle {
    if (secret.length !== SECRET_KEY_LEN) {
      throw new KobeError("input", "backend: secret key must be 32 bytes");
    }
    let keysObj: Keys;
    try {
      keysObj = Keys.fromSecretKey(secret);
    } catch (error) {
      rethrow("input", "backend: invalid secp256k1 secret key", error);
    }
    return issueKey({ keys: keysObj, conversationKeys: new Map() });
  }

  function releaseKey(record: KeyRecord): void {
    record.keys.secretKey.zeroize();
    for (const conv of record.conversationKeys.values()) {
      wipeBytes(conv);
    }
    record.conversationKeys.clear();
  }

  const backend: KobeBackend = {
    generateWallet: async (wordCount: WordCount) =>
      issueWallet(Wallet.generate(rng ? { wordCount, rng } : { wordCount })),

    importMnemonic: async (phrase: string) => issueWallet(Wallet.fromMnemonic(phrase)),

    importPasskeyPrf: async (prfOutput: Uint8Array) => issueWallet(passkeyWallet(prfOutput)),

    exportMnemonic: async (handle: WalletHandle) => requireWallet(handle).mnemonic(),

    sealWallet: async (handle: WalletHandle, dek: Uint8Array, context: string) => {
      const bytes = requireWallet(handle).mnemonicBytes();
      try {
        return seal(dek, bytes, context);
      } finally {
        wipeBytes(bytes);
      }
    },

    openWallet: async (sealed: Uint8Array, dek: Uint8Array, context: string) => {
      const plaintext = open(dek, sealed, context);
      try {
        return issueWallet(Wallet.fromMnemonic(new TextDecoder().decode(plaintext)));
      } finally {
        wipeBytes(plaintext);
      }
    },

    deriveNostrKey: async (handle: WalletHandle, account: number) => {
      assertU32Index(account, "account");
      const derived = new NostrDeriver(requireWallet(handle)).derive(account);
      const secret = derived.privateKeyBytes();
      try {
        return importSecret(secret);
      } finally {
        derived.dispose();
        wipeBytes(secret);
      }
    },

    importNostrKey: async (secretKey: Uint8Array) => importSecret(secretKey),

    exportNostrKey: async (handle: NostrKeyHandle) => requireKey(handle).keys.secretKey.bytes,

    importNsec: async (nsec: string) => {
      let decoded: ReturnType<typeof nip19.decode>;
      try {
        decoded = nip19.decode(nsec);
      } catch (error) {
        rethrow("input", "backend: invalid nsec", error);
      }
      if (decoded.type !== "nsec") {
        throw new KobeError("input", "backend: expected an nsec1… string");
      }
      const { data } = decoded;
      try {
        return importSecret(data);
      } finally {
        wipeBytes(data);
      }
    },

    exportNsec: async (handle: NostrKeyHandle) => {
      const secret = requireKey(handle).keys.secretKey.bytes;
      try {
        return nip19.nsecEncode(secret);
      } finally {
        wipeBytes(secret);
      }
    },

    nostrPublicKey: async (handle: NostrKeyHandle) => requireKey(handle).keys.publicKey,

    signEvent: async (handle: NostrKeyHandle, unsigned: UnsignedEvent) => {
      const record = requireKey(handle);
      if (unsigned.pubkey !== record.keys.publicKey) {
        throw new KobeError("input", "backend: unsigned event pubkey does not match the key");
      }
      let event;
      try {
        event = signEvent(unsigned, record.keys);
      } catch (error) {
        rethrow("input", "backend: cannot sign event", error);
      }
      return event;
    },

    nip44Encrypt: async (handle: NostrKeyHandle, peer: string, plaintext: string) => {
      const record = requireKey(handle);
      const conv = conversationKey(record, peer);
      let payload;
      try {
        payload = nip44.encrypt(plaintext, conv);
      } catch (error) {
        rethrow("input", "backend: invalid NIP-44 plaintext", error);
      }
      return payload;
    },

    nip44Decrypt: async (handle: NostrKeyHandle, peer: string, payload: string) => {
      const record = requireKey(handle);
      const conv = conversationKey(record, peer);
      let plaintext;
      try {
        plaintext = nip44.decrypt(payload, conv);
      } catch (error) {
        rethrow("decrypt", "backend: NIP-44 decryption failed", error);
      }
      return plaintext;
    },

    nip04Encrypt: async (handle: NostrKeyHandle, peer: string, plaintext: string) => {
      const record = requireKey(handle);
      const normalized = normalizePeer(peer);
      const secret = record.keys.secretKey.bytes;
      let payload;
      try {
        payload = nip04.encrypt(secret, normalized, plaintext);
      } catch (error) {
        rethrow("input", "backend: cannot NIP-04 encrypt", error);
      } finally {
        wipeBytes(secret);
      }
      return payload;
    },

    nip04Decrypt: async (handle: NostrKeyHandle, peer: string, ciphertext: string) => {
      const record = requireKey(handle);
      const normalized = normalizePeer(peer);
      const secret = record.keys.secretKey.bytes;
      let plaintext;
      try {
        plaintext = nip04.decrypt(secret, normalized, ciphertext);
      } catch (error) {
        rethrow("decrypt", "backend: NIP-04 decryption failed", error);
      } finally {
        wipeBytes(secret);
      }
      return plaintext;
    },

    release: (handle: WalletHandle | NostrKeyHandle) => {
      const wallet = wallets.get(handle);
      if (wallet) {
        wallets.delete(handle);
        wallet.dispose();
        return;
      }
      const record = keys.get(handle);
      if (record) {
        keys.delete(handle);
        releaseKey(record);
      }
    },

    revokeAll: () => {
      for (const wallet of wallets.values()) {
        wallet.dispose();
      }
      wallets.clear();
      for (const record of keys.values()) {
        releaseKey(record);
      }
      keys.clear();
    },
  };

  return backend;
}
