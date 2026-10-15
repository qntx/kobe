import { getPublicKey } from "@qntx/nostr";
import type { Event } from "@qntx/nostr";
import type { Factor, NostrImportInput, NullValue, UnwrapResult } from "@qntx/wallet/protocol";
import type { NostrKeyInfo } from "@qntx/wallet/types";

import { masterKey } from "../derive/hd.ts";
import { nostrKeyAt } from "../derive/templates.ts";
import { KernelError } from "../errors.ts";
import {
  generateSecretKey,
  secretKeyFromNcryptsec,
  secretKeyFromNsec,
  signEvent,
  unwrapGiftWrap,
} from "../nostr/pool.ts";
import { wipe } from "../secret/secret.ts";
import type { Secret } from "../secret/secret.ts";
import { seedFromEntropy } from "../seed/seed.ts";
import { encodeHeader, parseNostrKeyHeader } from "../vault/headers.ts";
import type { NostrKeyHeader } from "../vault/headers.ts";
import type { StoredRecord } from "../vault/store.ts";
import {
  establishOps,
  findRecord,
  makeFactor,
  nostrKeyInfo,
  openRecord,
  sealRecord,
  verifyFactor,
} from "../vault/vault.ts";
import type { KernelContext } from "./context.ts";
import { gate } from "./wallets.ts";

type StandaloneOrigin = "nsec" | "ncryptsec" | "generated" | "nip46-client";

function keyRecord(
  ctx: KernelContext,
  dek: Secret,
  secretKey: Uint8Array,
  header: NostrKeyHeader,
): StoredRecord {
  return sealRecord(
    ctx.platform,
    dek,
    "nostr-key",
    header.publicKey,
    encodeHeader(header),
    new Uint8Array(secretKey),
  );
}

function ensureNewKey(ctx: KernelContext, publicKey: string): void {
  if (ctx.image.records.some((r) => r.kind === "nostr-key" && r.id === publicKey)) {
    throw new KernelError("already-exists", "nostr key already exists");
  }
}

/**
 * Adds a standalone nostr key. Same create/import gate as wallets: on an uninitialized vault the
 * `factor` establishes it (meta + factor + record in one guarded commit); otherwise a session is
 * required and `factor` must be absent.
 */
async function addKey(
  ctx: KernelContext,
  secretKey: Uint8Array,
  origin: StandaloneOrigin,
  factor: Factor | undefined,
  requestSession: string | undefined,
): Promise<{ key: NostrKeyInfo; session: string }> {
  const gated = gate(ctx, factor, requestSession);
  const publicKey = getPublicKey(secretKey);
  ensureNewKey(ctx, publicKey);
  const createdAt = ctx.platform.now();
  const header: NostrKeyHeader = { publicKey, origin, createdAt };
  const record = keyRecord(ctx, gated.dek, secretKey, header);
  if (gated.uninitialized) {
    if (factor === undefined) {
      throw new KernelError("integrity", "unreachable: initial factor missing");
    }
    const storedFactor = await makeFactor(ctx.platform, factor, gated.dek);
    try {
      await ctx.commit(establishOps(storedFactor, [record]));
    } catch (error) {
      gated.dek.wipe();
      throw error;
    }
    ctx.pool.add(secretKey);
    return { key: nostrKeyInfo(header), session: ctx.session.open(gated.dek) };
  }
  await ctx.commit([{ op: "put-record", record }]);
  ctx.pool.add(secretKey);
  return { key: nostrKeyInfo(header), session: ctx.session.current().id };
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
      : await secretKeyFromNcryptsec(input.ncryptsec, input.password);
  try {
    return await addKey(ctx, secretKey, input.kind, params.factor, requestSession);
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
    return await addKey(ctx, secretKey, "generated", params.factor, requestSession);
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
    ctx.pool.add(secretKey);
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
      ctx.pool.add(secretKey);
      return nostrKeyInfo(header);
    } finally {
      wipe(secretKey);
    }
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
  const record = findRecord(ctx.image, "nostr-key", params.publicKey);
  const header = parseNostrKeyHeader(record.header);
  if (header.origin !== "nip46-client") {
    // Every other key requires re-verification before deletion.
    if (params.verify === undefined) {
      throw new KernelError("invalid-input", "factor verification is required");
    }
    await verifyFactor(ctx.platform, ctx.image, params.verify, dek);
  }
  await ctx.commit([{ op: "delete-record", kind: "nostr-key", id: params.publicKey }]);
  ctx.pool.remove(params.publicKey);
  return null;
}

export async function signEventCommand(
  ctx: KernelContext,
  params: {
    publicKey: string;
    event: {
      kind: number;
      created_at: number;
      tags: ReadonlyArray<ReadonlyArray<string>>;
      content: string;
      pubkey?: string;
    };
  },
  requestSession: string | undefined,
): Promise<Event> {
  ctx.session.require(requestSession);
  return signEvent(ctx.pool, params.publicKey, params.event);
}

export async function nip04Encrypt(
  ctx: KernelContext,
  params: { publicKey: string; peer: string; text: string },
  requestSession: string | undefined,
): Promise<string> {
  ctx.session.require(requestSession);
  return ctx.pool.get(params.publicKey).nip04Encrypt(params.peer, params.text);
}

export async function nip04Decrypt(
  ctx: KernelContext,
  params: { publicKey: string; peer: string; text: string },
  requestSession: string | undefined,
): Promise<string> {
  ctx.session.require(requestSession);
  return ctx.pool.get(params.publicKey).nip04Decrypt(params.peer, params.text);
}

export async function nip44Encrypt(
  ctx: KernelContext,
  params: { publicKey: string; peer: string; text: string },
  requestSession: string | undefined,
): Promise<string> {
  ctx.session.require(requestSession);
  return ctx.pool.get(params.publicKey).nip44Encrypt(params.peer, params.text);
}

export async function nip44Decrypt(
  ctx: KernelContext,
  params: { publicKey: string; peer: string; text: string },
  requestSession: string | undefined,
): Promise<string> {
  ctx.session.require(requestSession);
  return ctx.pool.get(params.publicKey).nip44Decrypt(params.peer, params.text);
}

export async function unwrapGiftWraps(
  ctx: KernelContext,
  params: { publicKey: string; events: ReadonlyArray<Event> },
  requestSession: string | undefined,
): Promise<{ results: ReadonlyArray<UnwrapResult> }> {
  ctx.session.require(requestSession);
  const results: UnwrapResult[] = [];
  for (const event of params.events) {
    // oxlint-disable-next-line eslint/no-await-in-loop -- batch results are produced in order, one wrap at a time
    results.push(await unwrapGiftWrap(ctx.pool, params.publicKey, event));
  }
  return { results };
}
