/// <reference types="node" />
/**
 * Regenerates vectors/protocol.json without importing kernel or @qntx/wallet code: representative
 * wire messages for PROTOCOL_VERSION 1. Uint8Array fields are written as `{ "$bytes": "<hex>" }`.
 *
 * Message shapes:
 *
 * - Request: `{ v: 1, id, method, session?, params }`
 * - Response: `{ v: 1, id, ok }` or `{ v: 1, id, err: { code, retryAt? } }`
 * - Event: `{ v: 1, event: "status", status }` or `{ v: 1, event: "locked", reason }`
 *
 * `check` names the contract a sample exercises:
 *
 * - `request`: the envelope rules plus `METHODS[method].params`
 * - `response:<method>`: `METHODS[method].result` on `ok`
 * - `responseError`: the `err` payload validator
 * - `event`: the `kernelEvent` validator
 *
 * Run from the repo root: bun scripts/vectors/protocol.ts
 */
import { writeFileSync } from "node:fs";

const SESSION = "00112233445566778899aabbccddeeff";
const DRAFT = "ffeeddccbbaa99887766554433221100";
const WALLET_ID = "0011223344556677";
const PUBLIC_KEY = "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917";
const PEER = "9ba1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f";
const SIG =
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const FACTOR_ID = "11223344556677889900aabbccddeeff";
const PRF = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const CREATED_AT = 1767225600000;
const EVENT_TIME = 1767225600;

const hexOf = (text: string): string =>
  Array.from(new TextEncoder().encode(text), (b) => b.toString(16).padStart(2, "0")).join("");
const $b = (hex: string): { $bytes: string } => ({ $bytes: hex });

const passwordFactor = { kind: "password", password: $b(hexOf("correct horse battery staple")) };
const passkeyFactor = {
  kind: "passkey",
  credentialId: $b("deadbeefcafe"),
  prf: $b(PRF),
};

const walletInfo = {
  walletId: WALLET_ID,
  origin: "mnemonic",
  words: 12,
  backedUp: true,
  createdAt: CREATED_AT,
};
const passwordFactorInfo = { kind: "password", id: FACTOR_ID, createdAt: CREATED_AT };
const standaloneKey = {
  ref: { kind: "standalone", id: PUBLIC_KEY },
  publicKey: PUBLIC_KEY,
  origin: "generated",
  backedUp: false,
  createdAt: CREATED_AT,
};
const derivedKey = {
  ref: { kind: "derived", walletId: WALLET_ID, groupIndex: 0 },
  publicKey: PEER,
  origin: "derived",
  createdAt: CREATED_AT,
};
const statusUnlocked = {
  protocol: 1,
  vault: "unlocked",
  factors: [passwordFactorInfo],
  wallets: [walletInfo],
  nostr: { keys: [standaloneKey, derivedKey] },
};
const signedEvent = {
  id: "e".repeat(64),
  pubkey: PUBLIC_KEY,
  sig: SIG,
  kind: 1,
  created_at: EVENT_TIME,
  tags: [["p", PEER, "wss://relay.example"]],
  content: "gm",
};

const requests: Array<{ name: string; message: Record<string, unknown> }> = [
  { name: "status", message: { v: 1, id: 1, method: "status", params: null } },
  {
    name: "vault.unlock",
    message: { v: 1, id: 2, method: "vault.unlock", params: { factor: passwordFactor } },
  },
  {
    name: "vault.reset",
    message: { v: 1, id: 3, method: "vault.reset", session: SESSION, params: null },
  },
  {
    name: "vault.addFactor",
    message: {
      v: 1,
      id: 4,
      method: "vault.addFactor",
      session: SESSION,
      params: { verify: passwordFactor, factor: passkeyFactor },
    },
  },
  {
    name: "vault.removeFactor",
    message: {
      v: 1,
      id: 5,
      method: "vault.removeFactor",
      session: SESSION,
      params: { verify: passwordFactor, id: FACTOR_ID },
    },
  },
  {
    name: "wallet.createWithPasskey",
    message: {
      v: 1,
      id: 6,
      method: "wallet.createWithPasskey",
      params: { credentialId: $b("deadbeefcafe"), prfWallet: $b(PRF) },
    },
  },
  {
    name: "wallet.restoreWithPasskey",
    message: {
      v: 1,
      id: 7,
      method: "wallet.restoreWithPasskey",
      params: {
        credentialId: $b("deadbeefcafe"),
        prfWallet: $b(PRF),
        factor: passwordFactor,
      },
    },
  },
  {
    name: "wallet.createMnemonic",
    message: { v: 1, id: 8, method: "wallet.createMnemonic", params: { words: 12 } },
  },
  {
    name: "wallet.confirmMnemonic",
    message: {
      v: 1,
      id: 9,
      method: "wallet.confirmMnemonic",
      params: {
        draft: DRAFT,
        answers: [$b(hexOf("legal")), $b(hexOf("winner")), $b(hexOf("thank"))],
      },
    },
  },
  {
    name: "wallet.discardMnemonic",
    message: { v: 1, id: 10, method: "wallet.discardMnemonic", params: { draft: DRAFT } },
  },
  {
    name: "wallet.importMnemonic",
    message: {
      v: 1,
      id: 11,
      method: "wallet.importMnemonic",
      params: {
        mnemonic: $b(
          hexOf("legal winner thank year wave sausage worth useful legal winner thank yellow"),
        ),
      },
    },
  },
  {
    name: "wallet.exportMnemonic",
    message: {
      v: 1,
      id: 12,
      method: "wallet.exportMnemonic",
      session: SESSION,
      params: { verify: passwordFactor, walletId: WALLET_ID },
    },
  },
  {
    name: "wallet.delete",
    message: {
      v: 1,
      id: 13,
      method: "wallet.delete",
      session: SESSION,
      params: { verify: passwordFactor, walletId: WALLET_ID },
    },
  },
  {
    name: "dataKeys.get",
    message: {
      v: 1,
      id: 14,
      method: "dataKeys.get",
      session: SESSION,
      params: { purpose: "backup" },
    },
  },
  {
    name: "nostr.importKey",
    message: {
      v: 1,
      id: 15,
      method: "nostr.importKey",
      params: { input: { kind: "nsec", nsec: $b(PRF) } },
    },
  },
  {
    name: "nostr.generateKey",
    message: { v: 1, id: 16, method: "nostr.generateKey", params: {} },
  },
  {
    name: "nostr.createNip46ClientKey",
    message: {
      v: 1,
      id: 17,
      method: "nostr.createNip46ClientKey",
      session: SESSION,
      params: null,
    },
  },
  {
    name: "nostr.removeKey",
    message: {
      v: 1,
      id: 18,
      method: "nostr.removeKey",
      session: SESSION,
      params: { publicKey: PUBLIC_KEY },
    },
  },
  {
    name: "nostr.exportKey",
    message: {
      v: 1,
      id: 19,
      method: "nostr.exportKey",
      session: SESSION,
      params: {
        verify: passwordFactor,
        publicKey: PUBLIC_KEY,
        format: { kind: "ncryptsec", password: $b(hexOf("export password")) },
      },
    },
  },
  {
    name: "nostr.signEvent",
    message: {
      v: 1,
      id: 20,
      method: "nostr.signEvent",
      session: SESSION,
      params: {
        publicKey: PUBLIC_KEY,
        event: {
          kind: 1,
          created_at: EVENT_TIME,
          tags: [["p", PEER, "wss://relay.example"]],
          content: "gm",
        },
      },
    },
  },
  {
    name: "nostr.nip44Encrypt",
    message: {
      v: 1,
      id: 21,
      method: "nostr.nip44Encrypt",
      session: SESSION,
      params: { publicKey: PUBLIC_KEY, peer: PEER, text: "hello" },
    },
  },
  {
    name: "nostr.unwrapGiftWraps",
    message: {
      v: 1,
      id: 22,
      method: "nostr.unwrapGiftWraps",
      session: SESSION,
      params: { publicKey: PUBLIC_KEY, events: [signedEvent] },
    },
  },
];

const accept = [
  ...requests.map(({ name, message }) => ({
    name: `request-${name}`,
    check: "request",
    message,
  })),
  {
    name: "response-ok-status",
    check: "response:status",
    message: { v: 1, id: 1, ok: statusUnlocked },
  },
  {
    name: "response-ok-vault.unlock",
    check: "response:vault.unlock",
    message: { v: 1, id: 2, ok: { session: SESSION } },
  },
  {
    name: "response-ok-vault.reset",
    check: "response:vault.reset",
    message: { v: 1, id: 3, ok: null },
  },
  {
    name: "response-ok-vault.addFactor",
    check: "response:vault.addFactor",
    message: {
      v: 1,
      id: 4,
      ok: {
        kind: "passkey",
        id: FACTOR_ID,
        credentialId: "3q2-78r-",
        createdAt: CREATED_AT,
      },
    },
  },
  {
    name: "response-ok-wallet.createMnemonic",
    check: "response:wallet.createMnemonic",
    message: {
      v: 1,
      id: 8,
      ok: { draft: DRAFT, words: $b(hexOf("legal winner thank year")), quiz: [0, 5, 11] },
    },
  },
  {
    name: "response-ok-wallet.importMnemonic",
    check: "response:wallet.importMnemonic",
    message: { v: 1, id: 11, ok: { wallet: walletInfo, session: SESSION } },
  },
  {
    name: "response-ok-dataKeys.get",
    check: "response:dataKeys.get",
    message: { v: 1, id: 14, ok: $b(PRF) },
  },
  {
    name: "response-ok-nostr.deriveKey",
    check: "response:nostr.deriveKey",
    message: { v: 1, id: 23, ok: derivedKey },
  },
  {
    name: "response-ok-nostr.signEvent",
    check: "response:nostr.signEvent",
    message: { v: 1, id: 20, ok: signedEvent },
  },
  {
    name: "response-ok-nostr.nip44Encrypt",
    check: "response:nostr.nip44Encrypt",
    message: { v: 1, id: 21, ok: "ciphertext?iv=1" },
  },
  {
    name: "response-err-wrong-password",
    check: "responseError",
    message: { v: 1, id: 2, err: { code: "wrong-password" } },
  },
  {
    name: "response-err-rate-limited",
    check: "responseError",
    message: { v: 1, id: 2, err: { code: "rate-limited", retryAt: CREATED_AT + 30_000 } },
  },
  {
    name: "event-status",
    check: "event",
    message: { v: 1, event: "status", status: statusUnlocked },
  },
  {
    name: "event-locked-idle",
    check: "event",
    message: { v: 1, event: "locked", reason: "idle" },
  },
  {
    name: "event-locked-invalidated",
    check: "event",
    message: { v: 1, event: "locked", reason: "invalidated" },
  },
];

const reject: Array<{ name: string; check: string; message: unknown }> = [
  {
    name: "request-extra-envelope-key",
    check: "request",
    message: { v: 1, id: 1, method: "status", params: null, debug: true },
  },
  {
    name: "request-prototype-named-envelope-key",
    check: "request",
    message: JSON.parse('{"v":1,"id":1,"method":"status","params":null,"__proto__":{}}') as unknown,
  },
  {
    name: "request-wrong-version",
    check: "request",
    message: { v: 2, id: 1, method: "status", params: null },
  },
  {
    name: "request-id-not-an-integer",
    check: "request",
    message: { v: 1, id: "1", method: "status", params: null },
  },
  {
    name: "request-unknown-method",
    check: "request",
    message: { v: 1, id: 1, method: "vault.nuke", params: null },
  },
  {
    name: "request-missing-params",
    check: "request",
    message: { v: 1, id: 1, method: "status" },
  },
  {
    name: "request-non-integer-number",
    check: "request",
    message: {
      v: 1,
      id: 1,
      method: "nostr.signEvent",
      session: SESSION,
      params: {
        publicKey: PUBLIC_KEY,
        event: { kind: 1.5, created_at: EVENT_TIME, tags: [], content: "" },
      },
    },
  },
  {
    name: "params-unknown-key",
    check: "request",
    message: {
      v: 1,
      id: 2,
      method: "vault.unlock",
      params: { factor: passwordFactor, extra: 1 },
    },
  },
  {
    name: "params-prototype-named-key",
    check: "request",
    message: {
      v: 1,
      id: 2,
      method: "vault.unlock",
      params: JSON.parse(`{"factor":${JSON.stringify(passwordFactor)},"toString":1}`) as unknown,
    },
  },
  {
    name: "params-wrong-type",
    check: "request",
    message: {
      v: 1,
      id: 2,
      method: "vault.unlock",
      params: { factor: { kind: "password", password: "correct horse battery staple" } },
    },
  },
  {
    name: "params-over-length-string",
    check: "request",
    message: {
      v: 1,
      id: 14,
      method: "dataKeys.get",
      session: SESSION,
      params: { purpose: "a-purpose-name-that-is-way-too-long" },
    },
  },
  {
    name: "params-session-wrong-type",
    check: "request",
    message: { v: 1, id: 14, method: "dataKeys.get", session: 42, params: { purpose: "backup" } },
  },
  {
    name: "response-wrong-result-shape",
    check: "response:vault.unlock",
    message: { v: 1, id: 2, ok: { session: 42 } },
  },
  {
    name: "response-err-unknown-code",
    check: "responseError",
    message: { v: 1, id: 2, err: { code: "nope" } },
  },
  {
    name: "response-err-extra-key",
    check: "responseError",
    message: { v: 1, id: 2, err: { code: "wrong-password", detail: "nope" } },
  },
  {
    name: "event-unknown-field",
    check: "event",
    message: { v: 1, event: "locked", reason: "idle", extra: true },
  },
  {
    name: "event-unknown-reason",
    check: "event",
    message: { v: 1, event: "locked", reason: "forgotten" },
  },
];

const out = {
  comment:
    'PROTOCOL_VERSION 1 wire samples generated by scripts/vectors/protocol.ts — independent of @qntx/wallet. Uint8Array fields are { "$bytes": "<hex>" }; `check` names the contract each sample exercises.',
  accept,
  reject,
};

writeFileSync("vectors/protocol.json", `${JSON.stringify(out, null, 2)}\n`);
console.log("wrote vectors/protocol.json");
