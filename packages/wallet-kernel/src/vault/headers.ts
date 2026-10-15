import { base64urlnopad } from "@scure/base";

import { KernelError } from "../errors.ts";

/**
 * Public headers are stored as raw JSON text and enter the envelope AAD verbatim, so encoding uses
 * a fixed key order and parsing is strict: exact key set, exact types and ranges; anything else is
 * `integrity`.
 */

export type EntropyHeader = {
  readonly walletId: string; // 16 lowercase hex
  readonly origin: "passkey" | "mnemonic";
  readonly words: 12 | 15 | 18 | 21 | 24;
  readonly backedUp: boolean;
  readonly createdAt: number; // non-negative safe integer
};

export type NostrKeyHeader =
  | {
      readonly publicKey: string; // 64 lowercase hex
      readonly origin: "derived";
      readonly walletId: string;
      readonly groupIndex: number;
      readonly createdAt: number;
    }
  | {
      readonly publicKey: string;
      readonly origin: "nsec" | "ncryptsec" | "generated" | "nip46-client";
      readonly createdAt: number;
    };

export type DataKeyHeader = {
  readonly purpose: string; // ^[a-z0-9-]{1,32}$
  readonly createdAt: number;
};

export type PasswordFactorHeader = {
  readonly salt: string; // base64url (no padding), decodes to 16 bytes
  readonly iterations: 600000;
  readonly createdAt: number;
};

export type PasskeyFactorHeader = {
  readonly credentialId: string; // base64url (no padding), decodes to 1–1023 bytes
  readonly createdAt: number;
};

export type VaultHeader =
  | EntropyHeader
  | NostrKeyHeader
  | DataKeyHeader
  | PasswordFactorHeader
  | PasskeyFactorHeader;

const PURPOSE_PATTERN = /^[a-z0-9-]{1,32}$/;
const WALLET_ID_PATTERN = /^[0-9a-f]{16}$/;
const PUBLIC_KEY_PATTERN = /^[0-9a-f]{64}$/;
const PASSWORD_ITERATIONS = 600000;

function failure(): KernelError {
  return new KernelError("integrity", "invalid vault header");
}

function parseObject(text: string): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch {
    throw failure();
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw failure();
  }
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- narrowed to a non-array object above
  return value as Record<string, unknown>;
}

/** Exact key set: every expected key present, nothing else. */
function expectKeys(object: Record<string, unknown>, keys: ReadonlyArray<string>): void {
  const actual = Object.keys(object);
  if (actual.length !== keys.length || !keys.every((key) => key in object)) {
    throw failure();
  }
}

function asWalletId(value: unknown): string {
  if (typeof value !== "string" || !WALLET_ID_PATTERN.test(value)) {
    throw failure();
  }
  return value;
}

function asPublicKey(value: unknown): string {
  if (typeof value !== "string" || !PUBLIC_KEY_PATTERN.test(value)) {
    throw failure();
  }
  return value;
}

function asCreatedAt(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw failure();
  }
  return value;
}

function asGroupIndex(value: unknown): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > 0x7fffffff
  ) {
    throw failure();
  }
  return value;
}

function asBase64url(value: unknown, min: number, max: number): string {
  if (typeof value !== "string") {
    throw failure();
  }
  let decoded: Uint8Array;
  try {
    decoded = base64urlnopad.decode(value);
  } catch {
    throw failure();
  }
  // Only canonical unpadded base64url is a valid header encoding.
  if (decoded.length < min || decoded.length > max || base64urlnopad.encode(decoded) !== value) {
    throw failure();
  }
  return value;
}

export function encodeHeader(header: VaultHeader): string {
  if ("publicKey" in header) {
    return header.origin === "derived"
      ? JSON.stringify({
          publicKey: header.publicKey,
          origin: header.origin,
          walletId: header.walletId,
          groupIndex: header.groupIndex,
          createdAt: header.createdAt,
        })
      : JSON.stringify({
          publicKey: header.publicKey,
          origin: header.origin,
          createdAt: header.createdAt,
        });
  }
  if ("credentialId" in header) {
    return JSON.stringify({ credentialId: header.credentialId, createdAt: header.createdAt });
  }
  if ("salt" in header) {
    return JSON.stringify({
      salt: header.salt,
      iterations: header.iterations,
      createdAt: header.createdAt,
    });
  }
  if ("purpose" in header) {
    return JSON.stringify({ purpose: header.purpose, createdAt: header.createdAt });
  }
  return JSON.stringify({
    walletId: header.walletId,
    origin: header.origin,
    words: header.words,
    backedUp: header.backedUp,
    createdAt: header.createdAt,
  });
}

function asEntropyOrigin(value: unknown): "passkey" | "mnemonic" {
  if (value !== "passkey" && value !== "mnemonic") {
    throw failure();
  }
  return value;
}

function asWords(value: unknown): 12 | 15 | 18 | 21 | 24 {
  if (value !== 12 && value !== 15 && value !== 18 && value !== 21 && value !== 24) {
    throw failure();
  }
  return value;
}

function asNostrStandaloneOrigin(
  value: unknown,
): "nsec" | "ncryptsec" | "generated" | "nip46-client" {
  if (
    value !== "nsec" &&
    value !== "ncryptsec" &&
    value !== "generated" &&
    value !== "nip46-client"
  ) {
    throw failure();
  }
  return value;
}

export function parseEntropyHeader(text: string): EntropyHeader {
  const object = parseObject(text);
  expectKeys(object, ["walletId", "origin", "words", "backedUp", "createdAt"]);
  const { backedUp } = object;
  if (typeof backedUp !== "boolean") {
    throw failure();
  }
  return {
    walletId: asWalletId(object["walletId"]),
    origin: asEntropyOrigin(object["origin"]),
    words: asWords(object["words"]),
    backedUp,
    createdAt: asCreatedAt(object["createdAt"]),
  };
}

export function parseNostrKeyHeader(text: string): NostrKeyHeader {
  const object = parseObject(text);
  const publicKey = asPublicKey(object["publicKey"]);
  const createdAt = asCreatedAt(object["createdAt"]);
  if (object["origin"] === "derived") {
    expectKeys(object, ["publicKey", "origin", "walletId", "groupIndex", "createdAt"]);
    return {
      publicKey,
      origin: "derived",
      walletId: asWalletId(object["walletId"]),
      groupIndex: asGroupIndex(object["groupIndex"]),
      createdAt,
    };
  }
  expectKeys(object, ["publicKey", "origin", "createdAt"]);
  return {
    publicKey,
    origin: asNostrStandaloneOrigin(object["origin"]),
    createdAt,
  };
}

export function parseDataKeyHeader(text: string): DataKeyHeader {
  const object = parseObject(text);
  expectKeys(object, ["purpose", "createdAt"]);
  const { purpose } = object;
  if (typeof purpose !== "string" || !PURPOSE_PATTERN.test(purpose)) {
    throw failure();
  }
  return { purpose, createdAt: asCreatedAt(object["createdAt"]) };
}

export function parsePasswordFactorHeader(text: string): PasswordFactorHeader {
  const object = parseObject(text);
  expectKeys(object, ["salt", "iterations", "createdAt"]);
  if (object["iterations"] !== PASSWORD_ITERATIONS) {
    throw failure();
  }
  return {
    salt: asBase64url(object["salt"], 16, 16),
    iterations: PASSWORD_ITERATIONS,
    createdAt: asCreatedAt(object["createdAt"]),
  };
}

export function parsePasskeyFactorHeader(text: string): PasskeyFactorHeader {
  const object = parseObject(text);
  expectKeys(object, ["credentialId", "createdAt"]);
  return {
    credentialId: asBase64url(object["credentialId"], 1, 1023),
    createdAt: asCreatedAt(object["createdAt"]),
  };
}
