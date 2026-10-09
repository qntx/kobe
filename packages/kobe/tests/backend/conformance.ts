/**
 * Reusable conformance suite for a {@link KobeBackend} implementation. The native backend
 * (`@qntx/kobe-native`) runs the same suite once it exists.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, test } from "vite-plus/test";

import { Keys, validateSignedEvent, verifyEvent } from "@qntx/nostr/core";
import { npubEncode } from "@qntx/nostr/nips/nip19";
import { KeysSigner } from "@qntx/nostr/signer";

import type { KobeBackend, NostrKeyHandle, WalletHandle } from "../../src/backend/index.ts";
import { KobeError } from "../../src/core/error.ts";

const root = join(import.meta.dirname, "../../../../vectors");

type PasskeyCase = { prf: string; mnemonic?: string; npub?: string; error?: string };
type Nip06Case = { mnemonic: string; privateKey: string; publicKey: string };

// oxlint-disable-next-line typescript/no-unnecessary-type-parameters -- call sites name the shape
function readVector<T>(file: string): T {
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- trusted shared vector JSON
  return JSON.parse(readFileSync(join(root, file), "utf8")) as T;
}

const PASSKEY_WALLET = readVector<{ cases: PasskeyCase[] }>("vault/passkey-wallet.json");
const NIP06 = readVector<{ cases: Nip06Case[] }>("nostr/nip06.json");

/** Rejects with the thrown `KobeError.code`; sentinels keep assertions unconditional. */
async function codeOf(f: () => Promise<unknown>): Promise<string> {
  try {
    await f();
    return "<no error thrown>";
  } catch (error) {
    return error instanceof KobeError ? error.code : "<non-KobeError thrown>";
  }
}

const passkeyCase = PASSKEY_WALLET.cases.find((c) => c.mnemonic !== undefined);
const [nip06Case] = NIP06.cases;

/**
 * Run the shared conformance checks against `create()`. Each test builds a fresh backend so handle
 * state never leaks between cases.
 */
export function describeBackendConformance(name: string, create: () => KobeBackend): void {
  describe(`KobeBackend conformance: ${name}`, () => {
    test("importPasskeyPrf reproduces the passkey-wallet vector", async () => {
      const backend = create();
      const wallet = await backend.importPasskeyPrf(hexToBytes(passkeyCase?.prf ?? ""));
      expect(await backend.exportMnemonic(wallet)).toBe(passkeyCase?.mnemonic);
      const key = await backend.deriveNostrKey(wallet, 0);
      expect(npubEncode(await backend.nostrPublicKey(key))).toBe(passkeyCase?.npub);
    });

    test("importMnemonic + deriveNostrKey reproduce NIP-06 TV1 account 0", async () => {
      const backend = create();
      const wallet = await backend.importMnemonic(nip06Case?.mnemonic ?? "");
      const key = await backend.deriveNostrKey(wallet, 0);
      expect(bytesToHex(await backend.exportNostrKey(key))).toBe(nip06Case?.privateKey);
      expect(await backend.nostrPublicKey(key)).toBe(nip06Case?.publicKey);
    });

    test("generateWallet returns a usable wallet handle", async () => {
      const backend = create();
      const wallet = await backend.generateWallet(12);
      const mnemonic = await backend.exportMnemonic(wallet);
      expect(mnemonic.split(" ")).toHaveLength(12);
      const key = await backend.deriveNostrKey(wallet, 0);
      expect(await backend.nostrPublicKey(key)).toMatch(/^[0-9a-f]{64}$/);
    });

    test("sealWallet/openWallet round-trip; wrong DEK and altered context fail with decrypt", async () => {
      const backend = create();
      const wallet = await backend.importMnemonic(nip06Case?.mnemonic ?? "");
      const dek = new Uint8Array(32).fill(7);
      const sealed = await backend.sealWallet(wallet, dek, "app/vault/test");
      const reopened = await backend.openWallet(sealed, dek, "app/vault/test");
      expect(await backend.exportMnemonic(reopened)).toBe(nip06Case?.mnemonic);

      const wrongDek = new Uint8Array(32).fill(8);
      expect(await codeOf(async () => backend.openWallet(sealed, wrongDek, "app/vault/test"))).toBe(
        "decrypt",
      );
      expect(await codeOf(async () => backend.openWallet(sealed, dek, "app/vault/other"))).toBe(
        "decrypt",
      );
    });

    test("signEvent produces a verifiable event; pubkey mismatch fails with input", async () => {
      const backend = create();
      const wallet = await backend.importMnemonic(nip06Case?.mnemonic ?? "");
      const key = await backend.deriveNostrKey(wallet, 0);
      const pubkey = await backend.nostrPublicKey(key);
      const unsigned = {
        kind: 1,
        created_at: 1_700_000_000,
        tags: [],
        content: "hello",
        pubkey,
      };
      const event = await backend.signEvent(key, unsigned);
      expect(validateSignedEvent(event)).toBe(true);
      expect(verifyEvent(event)).toBe(true);
      expect(event.pubkey).toBe(pubkey);

      const other = Keys.generate();
      expect(
        await codeOf(async () => backend.signEvent(key, { ...unsigned, pubkey: other.publicKey })),
      ).toBe("input");
    });

    test("NIP-44 round-trips with a peer KeysSigner in both directions", async () => {
      const backend = create();
      const peer = new KeysSigner(Keys.generate());
      const peerPubkey = await peer.getPublicKey();
      const key = await backend.importNostrKey(Keys.generate().secretKey.bytes);

      const outbound = await backend.nip44Encrypt(key, peerPubkey, "secret message");
      expect(await peer.nip44Decrypt?.(await backend.nostrPublicKey(key), outbound)).toBe(
        "secret message",
      );

      const inbound = await peer.nip44Encrypt?.(await backend.nostrPublicKey(key), "reply");
      expect(await backend.nip44Decrypt(key, peerPubkey, inbound ?? "")).toBe("reply");
    });

    test("tampered NIP-44 payload fails with decrypt; a bad peer fails with input", async () => {
      const backend = create();
      const key = await backend.importNostrKey(Keys.generate().secretKey.bytes);
      const peerPubkey = Keys.generate().publicKey;
      const payload = await backend.nip44Encrypt(key, peerPubkey, "m");
      const tampered = `${payload.slice(0, -4)}AAAA`;
      expect(await codeOf(async () => backend.nip44Decrypt(key, peerPubkey, tampered))).toBe(
        "decrypt",
      );
      expect(await codeOf(async () => backend.nip44Encrypt(key, "not-hex", "m"))).toBe("input");
      expect(await codeOf(async () => backend.nip44Decrypt(key, "not-hex", payload))).toBe("input");
    });

    test("NIP-04 round-trips with a peer KeysSigner in both directions", async () => {
      const backend = create();
      const peer = new KeysSigner(Keys.generate());
      const peerPubkey = await peer.getPublicKey();
      const key = await backend.importNostrKey(Keys.generate().secretKey.bytes);

      const outbound = await backend.nip04Encrypt(key, peerPubkey, "legacy dm");
      expect(await peer.nip04Decrypt?.(await backend.nostrPublicKey(key), outbound)).toBe(
        "legacy dm",
      );

      const inbound = await peer.nip04Encrypt?.(await backend.nostrPublicKey(key), "reply");
      expect(await backend.nip04Decrypt(key, peerPubkey, inbound ?? "")).toBe("reply");
    });

    test("nsec export → import round-trip preserves the public key", async () => {
      const backend = create();
      const key = await backend.importNostrKey(Keys.generate().secretKey.bytes);
      const nsec = await backend.exportNsec(key);
      const imported = await backend.importNsec(nsec);
      expect(await backend.nostrPublicKey(imported)).toBe(await backend.nostrPublicKey(key));
    });

    test("a bad nsec fails with input", async () => {
      const backend = create();
      expect(await codeOf(async () => backend.importNsec("nsec1bogus"))).toBe("input");
      expect(
        await codeOf(async () =>
          backend.importNsec(
            "nsec1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqypq00x0",
          ),
        ),
      ).toBe("input");
    });

    test("release invalidates a handle; wallet handles are not key handles", async () => {
      const backend = create();
      const wallet = await backend.importMnemonic(nip06Case?.mnemonic ?? "");
      const key = await backend.deriveNostrKey(wallet, 0);

      backend.release(wallet);
      expect(await codeOf(async () => backend.exportMnemonic(wallet))).toBe("handle");
      // A released wallet handle reused as a key handle is also stale.
      expect(
        await codeOf(async () =>
          // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- deliberate wrong-kind handle
          backend.nostrPublicKey(wallet as unknown as NostrKeyHandle),
        ),
      ).toBe("handle");
      // The key derived before the release stays usable.
      expect(bytesToHex(await backend.exportNostrKey(key))).toBe(nip06Case?.privateKey);

      backend.release(key);
      expect(await codeOf(async () => backend.nostrPublicKey(key))).toBe("handle");
      // A key handle is not a wallet handle.
      const key2 = await backend.importNostrKey(Keys.generate().secretKey.bytes);
      expect(
        await codeOf(async () =>
          // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- deliberate wrong-kind handle
          backend.exportMnemonic(key2 as unknown as WalletHandle),
        ),
      ).toBe("handle");
      // release is idempotent and never throws.
      backend.release(key);
      backend.release(key2);
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- never-issued handle
      backend.release(999 as WalletHandle);
    });

    test("revokeAll invalidates every handle", async () => {
      const backend = create();
      const wallet = await backend.importMnemonic(nip06Case?.mnemonic ?? "");
      const key = await backend.deriveNostrKey(wallet, 0);
      backend.revokeAll();
      expect(await codeOf(async () => backend.exportMnemonic(wallet))).toBe("handle");
      expect(await codeOf(async () => backend.nostrPublicKey(key))).toBe("handle");
    });
  });
}
