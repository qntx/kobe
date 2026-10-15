import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";

import { KernelError } from "../errors.ts";
import type { Pbkdf2, Random } from "../platform.ts";
import { Secret, decodeUtf8Secret, wipe } from "../secret/secret.ts";
import { factorContext, open, seal } from "./envelope.ts";
import type { StoredFactor } from "./store.ts";

const PASSWORD_ITERATIONS = 600000;

function decodePassword(password: Uint8Array): string {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(password);
  } catch {
    throw new KernelError("invalid-input", "password is not valid UTF-8");
  }
  return text.normalize("NFKC");
}

/**
 * Policy for a password factor at creation time: at least 10 Unicode code points after NFKC. Never
 * applied at unlock — a failing password there is just a wrong-password attempt.
 */
export function assertPasswordPolicy(password: Uint8Array): void {
  // oxlint-disable-next-line typescript/no-misused-spread -- counts Unicode code points of the NFKC password
  if ([...decodePassword(password)].length < 10) {
    throw new KernelError("invalid-input", "password must be at least 10 characters");
  }
}

/**
 * Password factor KEK: PBKDF2-HMAC-SHA256(UTF-8(NFKC(password)), salt, 600000, 32). The password
 * arrives as UTF-8 bytes (protocol rule) and is wiped afterwards.
 */
export async function passwordKek(
  password: Uint8Array,
  salt: Uint8Array,
  pbkdf2: Pbkdf2,
): Promise<Uint8Array> {
  const normalized = decodeUtf8Secret(password).normalize("NFKC"); // wipes `password`
  const normalizedBytes = utf8ToBytes(normalized);
  try {
    return await pbkdf2("sha256", normalizedBytes, salt, PASSWORD_ITERATIONS, 32);
  } finally {
    wipe(normalizedBytes);
  }
}

/**
 * Passkey factor KEK: HKDF-SHA256(ikm = prf, salt = credentialId, info =
 * "qntx-wallet/kek/passkey/v1", 32). Wipes `prf` in every case.
 */
export function passkeyKek(prf: Uint8Array, credentialId: Uint8Array): Uint8Array {
  try {
    if (prf.length !== 32) {
      throw new KernelError("invalid-input", "PRF output must be 32 bytes");
    }
    return hkdf(sha256, prf, credentialId, utf8ToBytes("qntx-wallet/kek/passkey/v1"), 32);
  } finally {
    wipe(prf);
  }
}

export type FactorRef = {
  readonly kind: StoredFactor["kind"];
  readonly id: string;
  readonly header: string; // raw JSON text, authenticated verbatim
};

/** Seals the DEK under a factor KEK; the result is the factor's `sealed` field. */
export function wrapDek(
  kek: Uint8Array,
  dek: Secret,
  factor: FactorRef,
  random: Random,
): Uint8Array {
  return dek.use((bytes) =>
    seal(kek, bytes, factorContext(factor.kind, factor.id), factor.header, random),
  );
}

/** Opens a stored factor's wrapped DEK. Authentication failure → `integrity`. */
export function unwrapDek(kek: Uint8Array, stored: StoredFactor): Secret {
  return Secret.take(
    open(kek, stored.sealed, factorContext(stored.kind, stored.id), stored.header),
  );
}
