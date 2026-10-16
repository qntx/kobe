/// <reference types="node" />
/**
 * Regenerates vectors/records.json without importing kernel code: each `text` is the exact JSON a
 * VAULT_FORMAT-2 store persists as a record/factor public header (or the vault meta object),
 * written out key by key in the documented order. `input` is the field set the parser returns.
 *
 * Key orders (must match the encoders):
 *
 * - Entropy: walletId, origin, words, backedUp, createdAt
 * - Data-key: purpose, createdAt
 * - Nostr derived: publicKey, origin, walletId, groupIndex, createdAt
 * - Nostr standalone (nsec, ncryptsec, generated): publicKey, origin, backedUp, createdAt
 * - Nostr nip46-client: publicKey, origin, createdAt (never carries backedUp)
 * - Password factor: salt, iterations, publicKey, createdAt
 * - Passkey factor: credentialId, publicKey, createdAt
 * - Vault meta: format, revision, keyId, failedAttempts, lastFailureAt
 *
 * Run from the repo root: bun scripts/vectors/records.ts
 */
import { writeFileSync } from "node:fs";

const PUBLIC_KEY = "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917";
const WALLET_ID = "0011223344556677";
const CREATED_AT = 1767225600000;

type Input = Record<string, unknown>;

/** The exact stored text for one vector, spelled out in the format's key order. */
function textOf(kind: string, input: Input): string {
  const i = input;
  switch (kind) {
    case "entropy":
      return JSON.stringify({
        walletId: i["walletId"],
        origin: i["origin"],
        words: i["words"],
        backedUp: i["backedUp"],
        createdAt: i["createdAt"],
      });
    case "data-key":
      return JSON.stringify({ purpose: i["purpose"], createdAt: i["createdAt"] });
    case "nostr-derived":
      return JSON.stringify({
        publicKey: i["publicKey"],
        origin: i["origin"],
        walletId: i["walletId"],
        groupIndex: i["groupIndex"],
        createdAt: i["createdAt"],
      });
    case "nostr-standalone":
      return JSON.stringify({
        publicKey: i["publicKey"],
        origin: i["origin"],
        backedUp: i["backedUp"],
        createdAt: i["createdAt"],
      });
    case "nostr-nip46-client":
      return JSON.stringify({
        publicKey: i["publicKey"],
        origin: i["origin"],
        createdAt: i["createdAt"],
      });
    case "factor-password":
      return JSON.stringify({
        salt: i["salt"],
        iterations: i["iterations"],
        publicKey: i["publicKey"],
        createdAt: i["createdAt"],
      });
    case "factor-passkey":
      return JSON.stringify({
        credentialId: i["credentialId"],
        publicKey: i["publicKey"],
        createdAt: i["createdAt"],
      });
    case "meta":
      return JSON.stringify({
        format: i["format"],
        revision: i["revision"],
        keyId: i["keyId"],
        failedAttempts: i["failedAttempts"],
        lastFailureAt: i["lastFailureAt"],
      });
    default:
      throw new Error(`unknown kind: ${kind}`);
  }
}

const cases: Array<{ name: string; kind: string; input: Input }> = [
  {
    name: "entropy-mnemonic",
    kind: "entropy",
    input: {
      walletId: WALLET_ID,
      origin: "mnemonic",
      words: 12,
      backedUp: true,
      createdAt: CREATED_AT,
    },
  },
  {
    name: "entropy-passkey",
    kind: "entropy",
    input: {
      walletId: WALLET_ID,
      origin: "passkey",
      words: 12,
      backedUp: false,
      createdAt: CREATED_AT,
    },
  },
  {
    name: "data-key",
    kind: "data-key",
    input: { purpose: "backup", createdAt: CREATED_AT },
  },
  {
    name: "nostr-derived",
    kind: "nostr-derived",
    input: {
      publicKey: PUBLIC_KEY,
      origin: "derived",
      walletId: WALLET_ID,
      groupIndex: 0,
      createdAt: CREATED_AT,
    },
  },
  {
    name: "nostr-nsec-backed-up",
    kind: "nostr-standalone",
    input: { publicKey: PUBLIC_KEY, origin: "nsec", backedUp: true, createdAt: CREATED_AT },
  },
  {
    name: "nostr-ncryptsec-unbacked",
    kind: "nostr-standalone",
    input: { publicKey: PUBLIC_KEY, origin: "ncryptsec", backedUp: false, createdAt: CREATED_AT },
  },
  {
    name: "nostr-generated-unbacked",
    kind: "nostr-standalone",
    input: { publicKey: PUBLIC_KEY, origin: "generated", backedUp: false, createdAt: CREATED_AT },
  },
  {
    name: "nostr-generated-backed-up",
    kind: "nostr-standalone",
    input: { publicKey: PUBLIC_KEY, origin: "generated", backedUp: true, createdAt: CREATED_AT },
  },
  {
    name: "nostr-nip46-client",
    kind: "nostr-nip46-client",
    input: { publicKey: PUBLIC_KEY, origin: "nip46-client", createdAt: CREATED_AT },
  },
  {
    name: "factor-password",
    kind: "factor-password",
    input: {
      salt: "ABEiM0RVZneImaq7zN3u_w",
      iterations: 600000,
      publicKey: "PxLfxal_e43m4jpaNusYyCfYFXOkFoQAQ1lQI1s0HUM",
      createdAt: CREATED_AT,
    },
  },
  {
    name: "factor-passkey",
    kind: "factor-passkey",
    input: {
      credentialId: "3q2-78r-",
      publicKey: "JqRYFT66Kmogg041szL7sSC6lKDj6VPKh-5HsP3DbAE",
      createdAt: CREATED_AT,
    },
  },
  {
    name: "meta",
    kind: "meta",
    input: {
      format: 2,
      revision: 1,
      keyId: "00112233445566778899aabbccddeeff",
      failedAttempts: 0,
      lastFailureAt: 0,
    },
  },
];

const out = {
  comment:
    "Exact public-header and vault-meta texts (VAULT_FORMAT 2) generated by scripts/vectors/records.ts — independent of the kernel. Each input is the parsed field set; text is the stored JSON.",
  vectors: cases.map(({ name, kind, input }) => ({
    name,
    kind,
    input,
    text: textOf(kind, input),
  })),
};

writeFileSync("vectors/records.json", `${JSON.stringify(out, null, 2)}\n`);
console.log("wrote vectors/records.json");
