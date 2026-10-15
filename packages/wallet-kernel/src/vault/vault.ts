import { equalBytes } from "@noble/ciphers/utils.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { base64urlnopad } from "@scure/base";

import type { Factor } from "@qntx/wallet/protocol";
import type { FactorInfo, WalletInfo } from "@qntx/wallet/types";

import { KernelError } from "../errors.ts";
import type { KernelPlatform } from "../platform.ts";
import type { Secret } from "../secret/secret.ts";
import { wipe } from "../secret/secret.ts";
import { open, recordContext, seal } from "./envelope.ts";
import { assertPasswordPolicy, passkeyKek, passwordKek, unwrapDek, wrapDek } from "./factors.ts";
import type { EntropyHeader } from "./headers.ts";
import { encodeHeader, parsePasskeyFactorHeader, parsePasswordFactorHeader } from "./headers.ts";
import type { StoredFactor, StoredRecord, StoreOp, VaultImage, VaultMeta } from "./store.ts";
import { VAULT_FORMAT } from "./store.ts";

/** Consecutive password failures → enforced wait: 30 s, 60 s, then 300 s from the 5th failure. */
const BACKOFF_MS = [30_000, 60_000, 300_000];
const FAILURES_BEFORE_BACKOFF = 5;

/**
 * The wall-clock wait after `failedAttempts` counted failures. The deadline is derived from the
 * stored `lastFailureAt` (not a stored retryAt), so a clock that moved backwards stays limited.
 */
function backoffDelay(failedAttempts: number): number {
  return failedAttempts >= FAILURES_BEFORE_BACKOFF
    ? (BACKOFF_MS[Math.min(failedAttempts - FAILURES_BEFORE_BACKOFF, BACKOFF_MS.length - 1)] ??
        300_000)
    : 0;
}

export const PASSWORD_FACTOR_ITERATIONS = 600000;

function factorId(random: KernelPlatform["random"]): string {
  return bytesToHex(random(16));
}

/**
 * A new factor's derived KEK plus the public header material. The KEK is caller-owned (wipe it or
 * hand it to `Secret.take`); the password variant's raw `salt` must be wiped after encoding.
 */
export type FactorKekMaterial =
  | { readonly kind: "password"; readonly kek: Uint8Array; readonly salt: Uint8Array }
  | { readonly kind: "passkey"; readonly kek: Uint8Array; readonly credentialId: Uint8Array };

/**
 * The single "derive KEK for a new factor" path, shared by `makeFactor` and mnemonic-draft pending
 * factors. The password policy applies only here: factor creation. `factor`'s secret bytes are
 * consumed (wiped) by the KDFs.
 */
export async function newFactorKek(
  platform: KernelPlatform,
  factor: Factor,
): Promise<FactorKekMaterial> {
  if (factor.kind === "password") {
    assertPasswordPolicy(factor.password);
    const salt = platform.random(16);
    const kek = await passwordKek(factor.password, salt, platform.pbkdf2);
    return { kind: "password", kek, salt };
  }
  const kek = passkeyKek(factor.prf, factor.credentialId);
  return { kind: "passkey", kek, credentialId: factor.credentialId };
}

type FactorHeaderMaterial =
  | { readonly kind: "password"; readonly salt: Uint8Array }
  | { readonly kind: "passkey"; readonly credentialId: Uint8Array };

/** Public header text for a new factor (raw bytes → base64url). */
export function factorHeader(material: FactorHeaderMaterial, createdAt: number): string {
  if (material.kind === "password") {
    return encodeHeader({
      salt: base64urlnopad.encode(material.salt),
      iterations: PASSWORD_FACTOR_ITERATIONS,
      createdAt,
    });
  }
  return encodeHeader({
    credentialId: base64urlnopad.encode(material.credentialId),
    createdAt,
  });
}

/** Builds a new factor record wrapping `dek`; see `newFactorKek` for the KEK/policy rules. */
export async function makeFactor(
  platform: KernelPlatform,
  factor: Factor,
  dek: Secret,
): Promise<StoredFactor> {
  const material = await newFactorKek(platform, factor);
  const id = factorId(platform.random);
  const header = factorHeader(material, platform.now());
  try {
    const sealed = wrapDek(material.kek, dek, { kind: material.kind, id, header }, platform.random);
    return { kind: material.kind, id, header, sealed };
  } finally {
    wipe(material.kek);
    if (material.kind === "password") {
      wipe(material.salt);
    }
  }
}

/** KEK for an existing factor record; `factor`'s secret bytes are consumed. */
async function kekFor(
  platform: KernelPlatform,
  factor: Factor,
  stored: StoredFactor,
): Promise<Uint8Array> {
  if (factor.kind === "password") {
    const { salt } = parsePasswordFactorHeader(stored.header);
    return passwordKek(factor.password, base64urlnopad.decode(salt), platform.pbkdf2);
  }
  return passkeyKek(factor.prf, factor.credentialId);
}

/**
 * One record's authenticated plaintext from the unlock pass. The vault layer opens every record
 * (AEAD bound to context plus the raw header) without interpreting kind or payload — the
 * composition point decides which module claims each plaintext and wipes the rest.
 */
export type OpenedRecord = {
  readonly kind: string;
  readonly id: string;
  readonly plaintext: Uint8Array;
};

/**
 * Unlocks the vault: factor unwrap against the caller-supplied fresh image, then one authentication
 * pass over every record (`open` binds each raw public header). Returns the DEK, every record
 * plaintext (ownership passes to the caller) and the vault keyId for the session.
 *
 * Password attempts are rate-limited on the stored counters: with no password factor the attempt is
 * `invalid-input` and never counted; an attempt rejected while backoff is armed is `rate-limited`
 * and never counted; a real miss commits `record-failure` through the given `commit` (atomic
 * against the shared store) and a success clears a nonzero counter with `reset-failures`. Passkey
 * unlock is never gated or counted.
 */
export async function unlock(
  platform: KernelPlatform,
  image: VaultImage,
  factor: Factor,
  commit: (ops: ReadonlyArray<StoreOp>) => Promise<void>,
): Promise<{ dek: Secret; records: OpenedRecord[]; keyId: string }> {
  const { meta } = image;
  if (meta === undefined) {
    throw new KernelError("invalid-input", "vault is not initialized");
  }

  let dek: Secret | undefined;
  if (factor.kind === "password") {
    const passwords = image.factors.filter((stored) => stored.kind === "password");
    if (passwords.length === 0) {
      throw new KernelError("invalid-input", "no password factor exists");
    }
    const retryAt = meta.lastFailureAt + backoffDelay(meta.failedAttempts);
    if (platform.now() < retryAt) {
      // A rejected attempt never ran PBKDF2: it is not counted, so retries during backoff
      // cannot push the horizon forward.
      throw new KernelError("rate-limited", "too many wrong passwords", retryAt);
    }
    for (const stored of passwords) {
      // oxlint-disable-next-line eslint/no-await-in-loop -- factors are tried sequentially, not in parallel
      const kek = await kekFor(platform, factor, stored);
      try {
        dek = unwrapDek(kek, stored);
        break;
      } catch (error) {
        if (!(error instanceof KernelError) || error.code !== "integrity") {
          throw error;
        }
      } finally {
        wipe(kek);
      }
    }
    if (dek === undefined) {
      await commit([{ op: "record-failure", at: platform.now() }]);
      throw new KernelError("wrong-password", "password did not open the vault");
    }
    if (meta.failedAttempts !== 0) {
      await commit([{ op: "reset-failures" }]);
    }
  } else {
    const wanted = base64urlnopad.encode(factor.credentialId);
    const stored = image.factors.find((f) => f.kind === "passkey" && credentialIdOf(f) === wanted);
    if (stored === undefined) {
      wipe(factor.prf);
      throw new KernelError("integrity", "no passkey factor matches the credential");
    }
    const kek = await kekFor(platform, factor, stored);
    try {
      dek = unwrapDek(kek, stored);
    } finally {
      wipe(kek);
    }
  }

  try {
    const records = authenticateRecords(dek, image.records);
    return { dek, records, keyId: meta.keyId };
  } catch (error) {
    dek.wipe();
    // The DEK opened but a record failed authentication: the vault contents are corrupt.
    // (A wrong factor fails earlier, while unwrapping the DEK, and is not corruption.)
    if (error instanceof KernelError) {
      throw new KernelError(error.code, error.message, error.retryAt, true);
    }
    throw error;
  }
}

function credentialIdOf(stored: StoredFactor): string | undefined {
  try {
    return parsePasskeyFactorHeader(stored.header).credentialId;
  } catch {
    return undefined;
  }
}

/** Opens every record once; the caller claims or wipes the returned plaintexts. */
function authenticateRecords(dek: Secret, records: ReadonlyArray<StoredRecord>): OpenedRecord[] {
  const opened: OpenedRecord[] = [];
  try {
    for (const record of records) {
      const plaintext = dek.use((bytes) =>
        open(bytes, record.sealed, recordContext(record.kind, record.id), record.header),
      );
      opened.push({ kind: record.kind, id: record.id, plaintext });
    }
    return opened;
  } catch (error) {
    for (const record of opened) {
      wipe(record.plaintext);
    }
    throw error;
  }
}

/**
 * Re-verifies a factor against the live session DEK: unwrap with the factor KEK and constant-time
 * compare. Password mismatches are `wrong-password`; everything else that fails is `integrity`. The
 * verify path never touches the rate limiter.
 */
export async function verifyFactor(
  platform: KernelPlatform,
  image: VaultImage,
  factor: Factor,
  dek: Secret,
): Promise<void> {
  const candidates = image.factors.filter((stored) => {
    if (factor.kind !== stored.kind) {
      return false;
    }
    return (
      factor.kind === "password" ||
      credentialIdOf(stored) === base64urlnopad.encode(factor.credentialId)
    );
  });
  let sawPasswordFactor = false;
  for (const stored of candidates) {
    // oxlint-disable-next-line eslint/no-await-in-loop -- factors are tried sequentially, not in parallel
    const kek = await kekFor(platform, factor, stored);
    try {
      const opened = unwrapDek(kek, stored);
      try {
        const same = opened.use((a) => dek.use((b) => equalBytes(a, b)));
        if (same) {
          return;
        }
      } finally {
        opened.wipe();
      }
      sawPasswordFactor = stored.kind === "password";
    } catch (error) {
      if (!(error instanceof KernelError) || error.code !== "integrity") {
        throw error;
      }
      sawPasswordFactor = stored.kind === "password";
    } finally {
      wipe(kek);
    }
  }
  if (factor.kind === "password") {
    throw new KernelError(
      sawPasswordFactor ? "wrong-password" : "invalid-input",
      "password did not verify",
    );
  }
  throw new KernelError("integrity", "factor did not verify");
}

export function sealRecord(
  platform: KernelPlatform,
  dek: Secret,
  kind: string,
  id: string,
  header: string,
  plaintext: Uint8Array,
): StoredRecord {
  const sealed = dek.use((bytes) =>
    seal(bytes, plaintext, recordContext(kind, id), header, platform.random),
  );
  return { kind, id, header, sealed };
}

export function openRecord(dek: Secret, record: StoredRecord): Uint8Array {
  return dek.use((bytes) =>
    open(bytes, record.sealed, recordContext(record.kind, record.id), record.header),
  );
}

export function findRecord(image: VaultImage, kind: string, id: string): StoredRecord {
  const record = image.records.find((r) => r.kind === kind && r.id === id);
  if (record === undefined) {
    throw new KernelError("not-found", "record not found");
  }
  return record;
}

/**
 * Ops that establish the vault in one atomic `init` commit, rejected by `conflict` if the store is
 * not empty. The caller keeps `keyId` for the session it opens afterwards.
 */
export function establishOps(
  platform: KernelPlatform,
  factor: StoredFactor,
  records: ReadonlyArray<StoredRecord>,
): { ops: StoreOp[]; keyId: string } {
  const keyId = bytesToHex(platform.random(16));
  const meta: VaultMeta = {
    format: VAULT_FORMAT,
    revision: 1,
    keyId,
    failedAttempts: 0,
    lastFailureAt: 0,
  };
  return {
    keyId,
    ops: [
      { op: "init", meta },
      { op: "put-factor", factor },
      ...records.map((record) => ({ op: "put-record" as const, record })),
    ],
  };
}

/** The `FactorInfo` a stored factor reports: kind, id, creation time, passkey credentialId. */
export function factorInfo(stored: StoredFactor): FactorInfo {
  if (stored.kind === "password") {
    return {
      kind: "password",
      id: stored.id,
      createdAt: parsePasswordFactorHeader(stored.header).createdAt,
    };
  }
  const header = parsePasskeyFactorHeader(stored.header);
  return {
    kind: "passkey",
    id: stored.id,
    credentialId: header.credentialId,
    createdAt: header.createdAt,
  };
}

/** The `WalletInfo` an entropy record's public header reports. */
export function walletInfo(header: EntropyHeader): WalletInfo {
  return {
    walletId: header.walletId,
    origin: header.origin,
    words: header.words,
    backedUp: header.backedUp,
    createdAt: header.createdAt,
  };
}
