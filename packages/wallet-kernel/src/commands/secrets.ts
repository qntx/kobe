import { utf8ToBytes } from "@noble/hashes/utils.js";

import type { Factor, NostrExportFormat } from "@qntx/wallet/protocol";

import { ncryptsecFromSecretKey, nsecFromSecretKey } from "../nostr/pool.ts";
import { wipe } from "../secret/secret.ts";
import { mnemonicFromEntropy } from "../seed/mnemonic.ts";
import { encodeHeader, parseNostrKeyHeader } from "../vault/headers.ts";
import { findRecord, openRecord, sealRecord, verifyFactor } from "../vault/vault.ts";
import type { KernelContext } from "./context.ts";

/** One-shot export: the mnemonic as UTF-8 bytes (the host wraps it in a wipeable buffer). */
export async function exportMnemonic(
  ctx: KernelContext,
  params: { verify: Factor; walletId: string },
  requestSession: string | undefined,
): Promise<Uint8Array> {
  const { dek } = ctx.session.require(requestSession);
  await verifyFactor(ctx.platform, ctx.image, params.verify, dek);
  const record = findRecord(ctx.image, "entropy", params.walletId);
  const entropy = openRecord(dek, record);
  try {
    return utf8ToBytes(mnemonicFromEntropy(entropy));
  } finally {
    wipe(entropy);
  }
}

export async function exportNostrKey(
  ctx: KernelContext,
  params: { verify: Factor; publicKey: string; format: NostrExportFormat },
  requestSession: string | undefined,
): Promise<Uint8Array> {
  const { dek } = ctx.session.require(requestSession);
  await verifyFactor(ctx.platform, ctx.image, params.verify, dek);
  const record = findRecord(ctx.image, "nostr-key", params.publicKey);
  const header = parseNostrKeyHeader(record.header);
  const secretKey = openRecord(dek, record);
  try {
    if (params.format.kind === "nsec") {
      return nsecFromSecretKey(secretKey);
    }
    // Key security byte: 0x01 for keys recoverable from the wallet (derived, generated),
    // 0x02 for keys that exist only here (imported, nip46-client).
    const ksb = header.origin === "derived" || header.origin === "generated" ? 0x01 : 0x02;
    return await ncryptsecFromSecretKey(secretKey, params.format.password, ksb);
  } finally {
    wipe(secretKey);
  }
}

/** Deterministic per-purpose data key; created on first use, stable across lock/unlock. */
export async function getDataKey(
  ctx: KernelContext,
  params: { purpose: string },
  requestSession: string | undefined,
): Promise<Uint8Array> {
  const { dek } = ctx.session.require(requestSession);
  const existing = ctx.image.records.find((r) => r.kind === "data-key" && r.id === params.purpose);
  if (existing !== undefined) {
    return openRecord(dek, existing);
  }
  const plaintext = ctx.platform.random(32);
  const header = encodeHeader({ purpose: params.purpose, createdAt: ctx.platform.now() });
  const record = sealRecord(ctx.platform, dek, "data-key", params.purpose, header, plaintext);
  await ctx.commit([{ op: "put-record", record }]);
  return new Uint8Array(plaintext);
}
