import { utf8ToBytes } from "@noble/hashes/utils.js";

import type { Factor } from "@qntx/wallet/protocol";

import { wipe } from "../secret/secret.ts";
import { mnemonicFromEntropy } from "../seed/mnemonic.ts";
import { encodeHeader, parseEntropyHeader } from "../vault/headers.ts";
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
  const header = parseEntropyHeader(record.header);
  const entropy = openRecord(dek, record);
  try {
    const exported = utf8ToBytes(mnemonicFromEntropy(entropy));
    // A successful export is the backup: re-seal the record with backup "mnemonic" — the public
    // header enters the AAD, so it must be sealed again. The guarded commit makes a concurrent
    // write conflict rather than silently lose the flag; a second export changes nothing.
    if (header.backup !== "mnemonic") {
      const updated = encodeHeader({ ...header, backup: "mnemonic" });
      await ctx.commit([
        {
          op: "put-record",
          record: sealRecord(
            ctx.platform,
            dek,
            "entropy",
            params.walletId,
            updated,
            new Uint8Array(entropy),
          ),
        },
      ]);
    }
    return exported;
  } finally {
    wipe(entropy);
  }
}

/**
 * Random per-purpose data key, generated on first use and stored per vault: stable across
 * lock/unlock and DEK rotation, lost on reset or on a restore to another device (callers must be
 * able to rebuild the data from it).
 */
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
