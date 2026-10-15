import { equalBytes } from "@noble/ciphers/utils.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { base64urlnopad } from "@scure/base";

import type { Factor } from "@qntx/wallet/protocol";
import type { FactorInfo, NostrKeyInfo, WalletInfo } from "@qntx/wallet/types";

import { KernelError } from "../errors.ts";
import type { KernelPlatform } from "../platform.ts";
import type { Secret } from "../secret/secret.ts";
import { wipe } from "../secret/secret.ts";
import { open, recordContext, seal } from "./envelope.ts";
import { assertPasswordPolicy, passkeyKek, passwordKek, unwrapDek, wrapDek } from "./factors.ts";
import type { EntropyHeader, NostrKeyHeader } from "./headers.ts";
import {
  encodeHeader,
  parseDataKeyHeader,
  parseEntropyHeader,
  parseNostrKeyHeader,
  parsePasskeyFactorHeader,
  parsePasswordFactorHeader,
} from "./headers.ts";
import type { StoredFactor, StoredRecord, StoreOp, VaultImage, VaultMeta } from "./store.ts";

/** Consecutive password failures → enforced wait: 30 s, 60 s, then 300 s from the 5th failure. */
const BACKOFF_MS = [30_000, 60_000, 300_000];
const FAILURES_BEFORE_BACKOFF = 5;

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
 * Unlocks the vault: rate limiting, factor unwrap, then one authentication pass over every record
 * (`open` binds each raw public header). Returns the DEK and the nostr-key plaintexts keyed by
 * public key; every other plaintext is wiped. Password failures count toward the rate limit;
 * passkey failures are `integrity` and do not.
 */
export async function unlock(
  platform: KernelPlatform,
  image: VaultImage,
  factor: Factor,
): Promise<{ dek: Secret; nostrKeys: Map<string, Uint8Array> }> {
  const { meta } = image;
  if (meta === undefined) {
    throw new KernelError("invalid-input", "vault is not initialized");
  }
  const now = platform.now();
  if (now < meta.retryAt) {
    throw new KernelError("rate-limited", "too many wrong passwords", meta.retryAt);
  }

  let dek: Secret | undefined;
  if (factor.kind === "password") {
    let lastError: KernelError | undefined;
    for (const stored of image.factors) {
      if (stored.kind !== "password") {
        continue;
      }
      // oxlint-disable-next-line eslint/no-await-in-loop -- factors are tried sequentially, not in parallel
      const kek = await kekFor(platform, factor, stored);
      try {
        dek = unwrapDek(kek, stored);
        break;
      } catch (error) {
        if (!(error instanceof KernelError)) {
          throw error;
        }
        lastError = error;
      } finally {
        wipe(kek);
      }
    }
    if (dek === undefined) {
      const failedAttempts = meta.failedAttempts + 1;
      const delay =
        failedAttempts >= FAILURES_BEFORE_BACKOFF
          ? (BACKOFF_MS[
              Math.min(failedAttempts - FAILURES_BEFORE_BACKOFF, BACKOFF_MS.length - 1)
            ] ?? 300_000)
          : 0;
      await platform.store.commit([
        {
          op: "put-meta",
          meta: { ...meta, failedAttempts, retryAt: delay > 0 ? now + delay : 0 },
        },
      ]);
      throw lastError === undefined
        ? new KernelError("invalid-input", "no password factor exists")
        : new KernelError("wrong-password", "password did not open the vault");
    }
    if (meta.failedAttempts !== 0 || meta.retryAt !== 0) {
      await platform.store.commit([
        { op: "put-meta", meta: { ...meta, failedAttempts: 0, retryAt: 0 } },
      ]);
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
    const nostrKeys = authenticateRecords(dek, image.records);
    return { dek, nostrKeys };
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

/** Opens every record once; keeps only nostr-key plaintexts, wipes the rest. */
function authenticateRecords(
  dek: Secret,
  records: ReadonlyArray<StoredRecord>,
): Map<string, Uint8Array> {
  const nostrKeys = new Map<string, Uint8Array>();
  try {
    for (const record of records) {
      const plaintext = dek.use((bytes) =>
        open(bytes, record.sealed, recordContext(record.kind, record.id), record.header),
      );
      if (record.kind === "nostr-key") {
        nostrKeys.set(record.id, plaintext);
      } else {
        wipe(plaintext);
      }
    }
    return nostrKeys;
  } catch (error) {
    for (const plaintext of nostrKeys.values()) {
      wipe(plaintext);
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
      if (!(error instanceof KernelError)) {
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
  kind: StoredRecord["kind"],
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

export function findRecord(
  image: VaultImage,
  kind: StoredRecord["kind"],
  id: string,
): StoredRecord {
  const record = image.records.find((r) => r.kind === kind && r.id === id);
  if (record === undefined) {
    throw new KernelError("not-found", "record not found");
  }
  return record;
}

/** Ops that establish the vault in one atomic commit, guarded against concurrent races. */
export function establishOps(
  factor: StoredFactor,
  records: ReadonlyArray<StoredRecord>,
): StoreOp[] {
  const meta: VaultMeta = { format: 1, failedAttempts: 0, retryAt: 0 };
  return [
    { op: "expect-uninitialized" },
    { op: "put-meta", meta },
    { op: "put-factor", factor },
    ...records.map((record) => ({ op: "put-record" as const, record })),
  ];
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

/** The `NostrKeyInfo` a nostr-key record's public header reports. */
export function nostrKeyInfo(header: NostrKeyHeader): NostrKeyInfo {
  return {
    ref:
      header.origin === "derived"
        ? { kind: "derived", walletId: header.walletId, groupIndex: header.groupIndex }
        : header.origin === "nip46-client"
          ? { kind: "nip46-client", id: header.publicKey }
          : { kind: "standalone", id: header.publicKey },
    publicKey: header.publicKey,
    origin: header.origin,
    createdAt: header.createdAt,
  };
}

/**
 * Snapshot contents for the `status` payload. Locked snapshots are display-only data from
 * unauthenticated public headers; a row whose header fails to parse is omitted from the lists and
 * flips `corrupted` — the kernel reports the vault corrupted rather than silently dropping identity
 * rows.
 */
export function snapshotContents(image: VaultImage): {
  factors: FactorInfo[];
  wallets: WalletInfo[];
  nostrKeys: NostrKeyInfo[];
  corrupted: boolean;
} {
  const factors: FactorInfo[] = [];
  const wallets: WalletInfo[] = [];
  const nostrKeys: NostrKeyInfo[] = [];
  let corrupted = false;
  for (const factor of image.factors) {
    try {
      factors.push(factorInfo(factor));
    } catch {
      corrupted = true;
    }
  }
  for (const record of image.records) {
    try {
      if (record.kind === "entropy") {
        wallets.push(walletInfo(parseEntropyHeader(record.header)));
      } else if (record.kind === "nostr-key") {
        nostrKeys.push(nostrKeyInfo(parseNostrKeyHeader(record.header)));
      } else {
        parseDataKeyHeader(record.header);
      }
    } catch {
      corrupted = true;
    }
  }
  return { factors, wallets, nostrKeys, corrupted };
}
