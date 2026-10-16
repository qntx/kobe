import { equalBytes } from "@noble/ciphers/utils.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { base64urlnopad } from "@scure/base";

import type { Factor } from "@qntx/wallet/protocol";
import type { FactorInfo, WalletInfo } from "@qntx/wallet/types";

import { KernelError } from "../errors.ts";
import type { KernelPlatform } from "../platform.ts";
import { Secret, wipe } from "../secret/secret.ts";
import { open, recordContext, seal } from "./envelope.ts";
import {
  assertPasswordPolicy,
  factorBindingOk,
  factorHeaderPublicKey,
  factorPublicKey,
  passkeyKek,
  passwordKek,
  unwrapDek,
  wrapDek,
} from "./factors.ts";
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

/** Public header text for a new factor (raw bytes → base64url). `publicKey` is not consumed. */
export function factorHeader(
  material: FactorHeaderMaterial,
  publicKey: Uint8Array,
  createdAt: number,
): string {
  const pk = base64urlnopad.encode(publicKey);
  if (material.kind === "password") {
    return encodeHeader({
      salt: base64urlnopad.encode(material.salt),
      iterations: PASSWORD_FACTOR_ITERATIONS,
      publicKey: pk,
      createdAt,
    });
  }
  return encodeHeader({
    credentialId: base64urlnopad.encode(material.credentialId),
    publicKey: pk,
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
  try {
    const publicKey = factorPublicKey(material.kek);
    const header = factorHeader(material, publicKey, platform.now());
    const sealed = wrapDek(dek, publicKey, { kind: material.kind, id, header }, platform.random);
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
 * One record's authenticated plaintext from an unlock or reconcile pass. The vault layer opens
 * every record (AEAD bound to context plus the raw header) without interpreting kind or payload —
 * the composition point decides which module claims each plaintext and wipes the rest.
 */
export type OpenedRecord = {
  readonly kind: string;
  readonly id: string;
  readonly plaintext: Uint8Array;
};

/**
 * Unlocks the vault: factor unwrap against the caller-supplied fresh image. Returns the DEK and the
 * vault keyId for the session; record and factor authentication happens in the reconcile pass that
 * follows (every row is "new" to an empty live state).
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
): Promise<{ dek: Secret; keyId: string }> {
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
        // `wrong-password` (the derived key missed the factor's public key) tries the next
        // password factor; corruption-marked integrity failures abort the attempt entirely.
        if (!(error instanceof KernelError) || error.code !== "wrong-password") {
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
      throw new KernelError("wrong-passkey", "no passkey factor matches the credential");
    }
    const kek = await kekFor(platform, factor, stored);
    try {
      dek = unwrapDek(kek, stored);
    } finally {
      wipe(kek);
    }
  }

  return { dek, keyId: meta.keyId };
}

function credentialIdOf(stored: StoredFactor): string | undefined {
  try {
    return parsePasskeyFactorHeader(stored.header).credentialId;
  } catch {
    return undefined;
  }
}

/**
 * Re-verifies a factor against the live session DEK: unwrap with the factor KEK and constant-time
 * compare. A public-key miss — `wrong-password`/`wrong-passkey` — tries the next candidate; every
 * other failure (including corruption-marked integrity) propagates immediately. When no candidate
 * matched, the miss is reported by factor kind: `wrong-password` (or `invalid-input` when no
 * password factor exists) or `wrong-passkey`. The verify path never touches the rate limiter.
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
      // A clean unwrap whose DEK differs is another vault's factor: try the next candidate.
    } catch (error) {
      if (
        !(error instanceof KernelError) ||
        (error.code !== "wrong-password" && error.code !== "wrong-passkey")
      ) {
        throw error;
      }
    } finally {
      wipe(kek);
    }
  }
  if (factor.kind === "password") {
    throw new KernelError(
      candidates.length > 0 ? "wrong-password" : "invalid-input",
      "password did not verify",
    );
  }
  throw new KernelError("wrong-passkey", "passkey did not verify");
}

/**
 * Rotates the vault: a fresh DEK and keyId; every record re-sealed under the new DEK keeping its
 * public header; every retained factor re-wraps the new DEK to the public key of a row whose
 * binding verified under the current DEK (an unverified row is never re-wrapped — it latches
 * corrupted instead); added factors are built under the new DEK. One guarded commit lands it all:
 * `set-key-id`, `delete-factor`s, `put-factor`s, `put-record`s.
 *
 * Everything secret is wiped on failure; on success the caller hands `dek` to `ctx.commit(ops, {
 * rotate })` or wipes it.
 */
export async function rotateVault(
  platform: KernelPlatform,
  image: VaultImage,
  dek: Secret,
  removed: ReadonlySet<string>,
  added: ReadonlyArray<Factor>,
): Promise<{ ops: StoreOp[]; dek: Secret; keyId: string; added: StoredFactor[] }> {
  const nextDek = Secret.take(platform.random(32));
  try {
    const keyId = bytesToHex(platform.random(16));
    const ops: StoreOp[] = [{ op: "set-key-id", keyId }];
    for (const id of removed) {
      ops.push({ op: "delete-factor", id });
    }
    const addedRows: StoredFactor[] = [];
    for (const factor of image.factors) {
      if (removed.has(factor.id)) {
        continue;
      }
      if (!factorBindingOk(dek, factor)) {
        throw new KernelError(
          "integrity",
          "factor binding does not match the vault",
          undefined,
          true,
        );
      }
      const publicKey = factorHeaderPublicKey(factor);
      const sealed = wrapDek(
        nextDek,
        publicKey,
        { kind: factor.kind, id: factor.id, header: factor.header },
        platform.random,
      );
      ops.push({
        op: "put-factor",
        factor: { kind: factor.kind, id: factor.id, header: factor.header, sealed },
      });
    }
    for (const factor of added) {
      // oxlint-disable-next-line eslint/no-await-in-loop -- each KEK derives sequentially
      const stored = await makeFactor(platform, factor, nextDek);
      addedRows.push(stored);
      ops.push({ op: "put-factor", factor: stored });
    }
    for (const record of image.records) {
      let plaintext: Uint8Array;
      try {
        plaintext = openRecord(dek, record);
      } catch {
        throw new KernelError("integrity", "record failed authentication", undefined, true);
      }
      try {
        const sealed = nextDek.use((bytes) =>
          seal(
            bytes,
            plaintext,
            recordContext(record.kind, record.id),
            record.header,
            platform.random,
          ),
        );
        ops.push({
          op: "put-record",
          record: {
            kind: record.kind,
            id: record.id,
            header: record.header,
            sealed,
          },
        });
      } finally {
        wipe(plaintext);
      }
    }
    return { ops, dek: nextDek, keyId, added: addedRows };
  } catch (error) {
    nextDek.wipe();
    throw error;
  }
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
    backup: header.backup,
    createdAt: header.createdAt,
  };
}
