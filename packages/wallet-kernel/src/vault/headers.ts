import { KernelError } from "../errors.ts";
import {
  asBase64url,
  asCreatedAt,
  asWalletId,
  expectKeys,
  headerFailure,
  headerObject,
} from "./header-codec.ts";

/**
 * The core-owned public headers: `entropy` and `data-key` records plus the two factor kinds.
 * Module-owned record kinds keep their parsers inside their module.
 */
export type EntropyHeader = {
  readonly walletId: string; // 16 lowercase hex
  readonly origin: "passkey" | "mnemonic";
  readonly words: 12 | 15 | 18 | 21 | 24;
  /** How the entropy survives this device: nothing, a synced passkey, or a written-down mnemonic. */
  readonly backup: "none" | "passkey" | "mnemonic";
  readonly createdAt: number; // non-negative safe integer
};

export type DataKeyHeader = {
  readonly purpose: string; // ^[a-z0-9-]{1,32}$
  readonly createdAt: number;
};

export type PasswordFactorHeader = {
  readonly salt: string; // base64url (no padding), decodes to 16 bytes
  readonly iterations: 600000;
  readonly publicKey: string; // base64url (no padding) X25519 wrapping key, 32 bytes
  readonly createdAt: number;
};

export type PasskeyFactorHeader = {
  readonly credentialId: string; // base64url (no padding), decodes to 1–1023 bytes
  readonly publicKey: string; // base64url (no padding) X25519 wrapping key, 32 bytes
  readonly createdAt: number;
};

export type CoreHeader = EntropyHeader | DataKeyHeader | PasswordFactorHeader | PasskeyFactorHeader;

const PURPOSE_PATTERN = /^[a-z0-9-]{1,32}$/;
const PASSWORD_ITERATIONS = 600000;

export function encodeHeader(header: CoreHeader): string {
  if ("credentialId" in header) {
    return JSON.stringify({
      credentialId: header.credentialId,
      publicKey: header.publicKey,
      createdAt: header.createdAt,
    });
  }
  if ("salt" in header) {
    return JSON.stringify({
      salt: header.salt,
      iterations: header.iterations,
      publicKey: header.publicKey,
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
    backup: header.backup,
    createdAt: header.createdAt,
  });
}

function asEntropyOrigin(value: unknown): "passkey" | "mnemonic" {
  if (value !== "passkey" && value !== "mnemonic") {
    throw headerFailure();
  }
  return value;
}

function asWords(value: unknown): 12 | 15 | 18 | 21 | 24 {
  if (value !== 12 && value !== 15 && value !== 18 && value !== 21 && value !== 24) {
    throw headerFailure();
  }
  return value;
}

export function parseEntropyHeader(text: string): EntropyHeader {
  const object = headerObject(text);
  expectKeys(object, ["walletId", "origin", "words", "backup", "createdAt"]);
  const { backup } = object;
  if (backup !== "none" && backup !== "passkey" && backup !== "mnemonic") {
    throw headerFailure();
  }
  return {
    walletId: asWalletId(object["walletId"]),
    origin: asEntropyOrigin(object["origin"]),
    words: asWords(object["words"]),
    backup,
    createdAt: asCreatedAt(object["createdAt"]),
  };
}

export function parseDataKeyHeader(text: string): DataKeyHeader {
  const object = headerObject(text);
  expectKeys(object, ["purpose", "createdAt"]);
  const { purpose } = object;
  if (typeof purpose !== "string" || !PURPOSE_PATTERN.test(purpose)) {
    throw headerFailure();
  }
  return { purpose, createdAt: asCreatedAt(object["createdAt"]) };
}

export function parsePasswordFactorHeader(text: string): PasswordFactorHeader {
  const object = headerObject(text);
  expectKeys(object, ["salt", "iterations", "publicKey", "createdAt"]);
  const { iterations } = object;
  if (typeof iterations !== "number" || !Number.isSafeInteger(iterations)) {
    throw headerFailure();
  }
  if (iterations !== PASSWORD_ITERATIONS) {
    // A well-formed header with different KDF parameters came from another build.
    throw new KernelError("unsupported", "password factor uses unknown KDF parameters");
  }
  return {
    salt: asBase64url(object["salt"], 16, 16),
    iterations: PASSWORD_ITERATIONS,
    publicKey: asBase64url(object["publicKey"], 32, 32),
    createdAt: asCreatedAt(object["createdAt"]),
  };
}

export function parsePasskeyFactorHeader(text: string): PasskeyFactorHeader {
  const object = headerObject(text);
  expectKeys(object, ["credentialId", "publicKey", "createdAt"]);
  return {
    credentialId: asBase64url(object["credentialId"], 1, 1023),
    publicKey: asBase64url(object["publicKey"], 32, 32),
    createdAt: asCreatedAt(object["createdAt"]),
  };
}
