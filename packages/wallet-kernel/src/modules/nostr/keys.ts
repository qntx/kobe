import { getPublicKey } from "@qntx/nostr";
import type { Factor, NostrExportFormat, NostrImportInput, NullValue } from "@qntx/wallet/protocol";
import type { NostrKeyInfo } from "@qntx/wallet/types";

import type { KernelContext } from "../../commands/context.ts";
import { commitRecords, gate } from "../../commands/wallets.ts";
import { masterKey } from "../../derive/hd.ts";
import { KernelError } from "../../errors.ts";
import { wipe } from "../../secret/secret.ts";
import type { Secret } from "../../secret/secret.ts";
import { seedFromEntropy } from "../../seed/seed.ts";
import type { StoredRecord } from "../../vault/store.ts";
import { findRecord, openRecord, sealRecord, verifyFactor } from "../../vault/vault.ts";
import { nostrKeyAt } from "./derive.ts";
import {
  generateSecretKey,
  ncryptsecFromSecretKey,
  nsecFromSecretKey,
  secretKeyFromNcryptsec,
  secretKeyFromNsec,
} from "./pool.ts";
import type { NostrKeyHeader } from "./record.ts";
import {
  encodeNostrKeyHeader,
  NOSTR_KEY_KIND,
  nostrKeyInfo,
  parseNostrKeyHeader,
} from "./record.ts";

type StandaloneOrigin = "nsec" | "ncryptsec" | "generated";

function keyRecord(
  ctx: KernelContext,
  dek: Secret,
  secretKey: Uint8Array,
  header: NostrKeyHeader,
): StoredRecord {
  return sealRecord(
    ctx.platform,
    dek,
    NOSTR_KEY_KIND,
    header.publicKey,
    encodeNostrKeyHeader(header),
    new Uint8Array(secretKey),
  );
}

function ensureNewKey(ctx: KernelContext, publicKey: string): void {
  if (ctx.image.records.some((r) => r.kind === NOSTR_KEY_KIND && r.id === publicKey)) {
    throw new KernelError("already-exists", "nostr key already exists");
  }
}

/**
 * Adds a standalone nostr key. Same create/import gate as wallets: on an uninitialized vault the
 * `factor` establishes it (meta + factor + record in one guarded commit); otherwise a session is
 * required and `factor` must be absent. The signer goes live when the committed image reconciles —
 * command handlers never touch the pool.
 */
async function addKey(
  ctx: KernelContext,
  secretKey: Uint8Array,
  origin: StandaloneOrigin,
  backedUp: boolean,
  factor: Factor | undefined,
  requestSession: string | undefined,
): Promise<{ key: NostrKeyInfo; session: string }> {
  const gated = gate(ctx, factor, requestSession);
  const publicKey = getPublicKey(secretKey);
  ensureNewKey(ctx, publicKey);
  const header: NostrKeyHeader = {
    publicKey,
    origin,
    backedUp,
    createdAt: ctx.platform.now(),
  };
  const record = keyRecord(ctx, gated.dek, secretKey, header);
  const session = await commitRecords(ctx, gated, factor, [record]);
  return { key: nostrKeyInfo(header), session };
}

export async function importKey(
  ctx: KernelContext,
  params: { input: NostrImportInput; factor?: Factor },
  requestSession: string | undefined,
): Promise<{ key: NostrKeyInfo; session: string }> {
  const { input } = params;
  const secretKey =
    input.kind === "nsec"
      ? secretKeyFromNsec(input.nsec)
      : await secretKeyFromNcryptsec(
          input.ncryptsec,
          input.password,
          ctx.platform.policy.maxScryptLogN,
        );
  try {
    // An imported key is already backed up — the caller holds the source material.
    return await addKey(ctx, secretKey, input.kind, true, params.factor, requestSession);
  } finally {
    wipe(secretKey);
  }
}

export async function generateKey(
  ctx: KernelContext,
  params: { factor?: Factor },
  requestSession: string | undefined,
): Promise<{ key: NostrKeyInfo; session: string }> {
  const secretKey = generateSecretKey(ctx.platform.random);
  try {
    return await addKey(ctx, secretKey, "generated", false, params.factor, requestSession);
  } finally {
    wipe(secretKey);
  }
}

export async function createNip46ClientKey(
  ctx: KernelContext,
  requestSession: string | undefined,
): Promise<NostrKeyInfo> {
  const { dek } = ctx.session.require(requestSession);
  const secretKey = generateSecretKey(ctx.platform.random);
  try {
    const publicKey = getPublicKey(secretKey);
    ensureNewKey(ctx, publicKey);
    const header: NostrKeyHeader = {
      publicKey,
      origin: "nip46-client",
      createdAt: ctx.platform.now(),
    };
    await ctx.commit([{ op: "put-record", record: keyRecord(ctx, dek, secretKey, header) }]);
    return nostrKeyInfo(header);
  } finally {
    wipe(secretKey);
  }
}

export async function deriveKey(
  ctx: KernelContext,
  params: { walletId: string; groupIndex: number },
  requestSession: string | undefined,
): Promise<NostrKeyInfo> {
  const { dek } = ctx.session.require(requestSession);
  const record = findRecord(ctx.image, "entropy", params.walletId);
  const entropy = openRecord(dek, record);
  const seed = await seedFromEntropy(entropy, ctx.platform.pbkdf2);
  wipe(entropy);
  const master = masterKey(seed);
  wipe(seed);
  try {
    const secretKey = nostrKeyAt(master, params.groupIndex);
    try {
      const publicKey = getPublicKey(secretKey);
      ensureNewKey(ctx, publicKey);
      const header: NostrKeyHeader = {
        publicKey,
        origin: "derived",
        walletId: params.walletId,
        groupIndex: params.groupIndex,
        createdAt: ctx.platform.now(),
      };
      await ctx.commit([{ op: "put-record", record: keyRecord(ctx, dek, secretKey, header) }]);
      return nostrKeyInfo(header);
    } finally {
      wipe(secretKey);
    }
  } finally {
    master.wipePrivateData();
  }
}

export async function discover(
  ctx: KernelContext,
  params: { walletId: string; from: number; count: number },
  requestSession: string | undefined,
): Promise<{ keys: Array<{ groupIndex: number; publicKey: string }> }> {
  const { dek } = ctx.session.require(requestSession);
  const record = findRecord(ctx.image, "entropy", params.walletId);
  const entropy = openRecord(dek, record);
  const keys: Array<{ groupIndex: number; publicKey: string }> = [];
  const seed = await seedFromEntropy(entropy, ctx.platform.pbkdf2);
  wipe(entropy);
  const master = masterKey(seed);
  wipe(seed);
  try {
    for (let i = 0; i < params.count; i++) {
      const groupIndex = params.from + i;
      const secretKey = nostrKeyAt(master, groupIndex);
      keys.push({ groupIndex, publicKey: getPublicKey(secretKey) });
      wipe(secretKey);
    }
    return { keys };
  } finally {
    master.wipePrivateData();
  }
}

export async function removeKey(
  ctx: KernelContext,
  params: { publicKey: string; verify?: Factor },
  requestSession: string | undefined,
): Promise<NullValue> {
  const { dek } = ctx.session.require(requestSession);
  const record = findRecord(ctx.image, NOSTR_KEY_KIND, params.publicKey);
  const header = parseNostrKeyHeader(record.header);
  if (header.origin !== "nip46-client") {
    // Every other key requires re-verification before deletion.
    if (params.verify === undefined) {
      throw new KernelError("invalid-input", "factor verification is required");
    }
    await verifyFactor(ctx.platform, ctx.image, params.verify, dek);
  }
  // Reconciliation forgets the live signer once the delete lands.
  await ctx.commit([{ op: "delete-record", kind: NOSTR_KEY_KIND, id: params.publicKey }]);
  return null;
}

export async function exportKey(
  ctx: KernelContext,
  params: { verify: Factor; publicKey: string; format: NostrExportFormat },
  requestSession: string | undefined,
): Promise<Uint8Array> {
  const { dek } = ctx.session.require(requestSession);
  await verifyFactor(ctx.platform, ctx.image, params.verify, dek);
  const record = findRecord(ctx.image, NOSTR_KEY_KIND, params.publicKey);
  const header = parseNostrKeyHeader(record.header);
  const secretKey = openRecord(dek, record);
  try {
    const exported =
      params.format.kind === "nsec"
        ? nsecFromSecretKey(secretKey)
        : await ncryptsecFromSecretKey(secretKey, params.format.password);
    // A successful export is the backup: re-seal the standalone record with backedUp: true.
    // The guarded commit makes a concurrent write conflict rather than silently lose the flag.
    if (header.origin !== "derived" && header.origin !== "nip46-client" && !header.backedUp) {
      const updated: NostrKeyHeader = { ...header, backedUp: true };
      await ctx.commit([
        {
          op: "put-record",
          record: keyRecord(ctx, dek, secretKey, updated),
        },
      ]);
    }
    return exported;
  } finally {
    wipe(secretKey);
  }
}
