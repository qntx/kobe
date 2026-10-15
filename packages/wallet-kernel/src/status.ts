import { PROTOCOL_VERSION } from "@qntx/wallet/protocol";
import type { FactorInfo, NostrKeyInfo, StatusPayload, WalletInfo } from "@qntx/wallet/types";

import type { KernelContext, VaultHooks } from "./commands/context.ts";
import type { NostrModule } from "./modules/nostr/index.ts";
import { parseDataKeyHeader, parseEntropyHeader } from "./vault/headers.ts";
import type { StoredRecord, VaultImage } from "./vault/store.ts";
import { factorInfo, walletInfo } from "./vault/vault.ts";

/**
 * Snapshot contents for the `status` payload — the record-ownership composition point. The core
 * parses the kinds it owns (entropy, data-key), claimed records are partitioned per module and each
 * module's own status function is called explicitly, and a stored kind nobody claims marks the
 * vault corrupted: fail closed, because a build that does not know a stored kind must not silently
 * drop it. Locked snapshots are display-only data from unauthenticated public headers.
 */
export function statusContents(
  image: VaultImage,
  modules: ReadonlyArray<VaultHooks>,
  nostr: NostrModule,
): {
  factors: FactorInfo[];
  wallets: WalletInfo[];
  keys: ReadonlyArray<NostrKeyInfo>;
  corrupted: boolean;
} {
  const factors: FactorInfo[] = [];
  const wallets: WalletInfo[] = [];
  const owned: StoredRecord[] = [];
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
      } else if (record.kind === "data-key") {
        parseDataKeyHeader(record.header);
      } else if (modules.some((module) => module.ownsRecord(record.kind))) {
        owned.push(record);
      } else {
        corrupted = true;
      }
    } catch {
      corrupted = true;
    }
  }
  const section = nostr.status(owned.filter((record) => nostr.vault.ownsRecord(record.kind)));
  return {
    factors,
    wallets,
    keys: section.keys,
    corrupted: corrupted || section.corrupted,
  };
}

/** The `status` payload for the current session + image; shared by `status` and `postStatus`. */
export function statusPayload(ctx: KernelContext, nostr: NostrModule): StatusPayload {
  const { factors, wallets, keys } = statusContents(ctx.image, ctx.modules, nostr);
  return {
    protocol: PROTOCOL_VERSION,
    vault: ctx.corrupted ? "corrupted" : ctx.session.status,
    factors,
    wallets,
    nostr: { keys },
  };
}
