/**
 * The nostr module: the nostr-key record kind, its signer pool, and every nostr.* command. Wired
 * once in kernel.ts — the VaultHooks give the core the explicit seams (record ownership, reconcile
 * claim/forget, lock dispose, wallet-delete ops) without the core knowing what a nostr key is;
 * `status` produces the module's snapshot section, called from status.ts.
 */
import type { MethodName, NOSTR_METHODS } from "@qntx/wallet/protocol";
import type { NostrKeyInfo } from "@qntx/wallet/types";

import type { Handler, VaultHooks } from "../../commands/context.ts";
import type { StoreOp, StoredRecord } from "../../vault/store.ts";
import type { OpenedRecord } from "../../vault/vault.ts";
import * as keys from "./keys.ts";
import * as ops from "./ops.ts";
import { SignerPool } from "./pool.ts";
import { NOSTR_KEY_KIND, nostrStatus, parseNostrKeyHeader } from "./record.ts";

export type NostrModule = {
  readonly vault: VaultHooks;
  readonly handlers: { [M in keyof typeof NOSTR_METHODS & MethodName]: Handler<M> };
  /**
   * The module's status section, parsed from its own records (status.ts partitions them by
   * ownership). A record whose header fails the module's parser reports `corrupted`.
   */
  readonly status: (records: ReadonlyArray<StoredRecord>) => {
    readonly keys: ReadonlyArray<NostrKeyInfo>;
    readonly corrupted: boolean;
  };
};

export function createNostrModule(): NostrModule {
  const pool = new SignerPool();

  const vault: VaultHooks = {
    ownsRecord: (kind) => kind === NOSTR_KEY_KIND,

    claimUnlocked: (records) => {
      const unclaimed: OpenedRecord[] = [];
      for (const record of records) {
        if (record.kind === NOSTR_KEY_KIND) {
          // Ownership transfers here: pool.add wipes the plaintext into the signer.
          pool.add(record.plaintext);
        } else {
          unclaimed.push(record);
        }
      }
      return unclaimed;
    },

    forget: (kind, id) => {
      if (kind === NOSTR_KEY_KIND) {
        pool.remove(id);
      }
    },

    lock: () => {
      pool.dispose();
    },

    walletDeleteOps: (image, walletId) => {
      const ops: StoreOp[] = [];
      for (const record of image.records) {
        if (record.kind !== NOSTR_KEY_KIND) {
          continue;
        }
        const header = parseNostrKeyHeader(record.header);
        if (header.origin === "derived" && header.walletId === walletId) {
          ops.push({ op: "delete-record", kind: NOSTR_KEY_KIND, id: record.id });
        }
      }
      return ops;
    },
  };

  const handlers: { [M in keyof typeof NOSTR_METHODS & MethodName]: Handler<M> } = {
    "nostr.discover": async (ctx, params, session) => keys.discover(ctx, params, session),
    "nostr.deriveKey": async (ctx, params, session) => keys.deriveKey(ctx, params, session),
    "nostr.importKey": async (ctx, params, session) => keys.importKey(ctx, params, session),
    "nostr.generateKey": async (ctx, params, session) => keys.generateKey(ctx, params, session),
    "nostr.createNip46ClientKey": async (ctx, _params, session) =>
      keys.createNip46ClientKey(ctx, session),
    "nostr.removeKey": async (ctx, params, session) => keys.removeKey(ctx, params, session),
    "nostr.exportKey": async (ctx, params, session) => keys.exportKey(ctx, params, session),
    "nostr.signEvent": async (ctx, params, session) => ops.sign(ctx, pool, params, session),
    "nostr.nip04Encrypt": async (ctx, params, session) =>
      ops.nip04Encrypt(ctx, pool, params, session),
    "nostr.nip04Decrypt": async (ctx, params, session) =>
      ops.nip04Decrypt(ctx, pool, params, session),
    "nostr.nip44Encrypt": async (ctx, params, session) =>
      ops.nip44Encrypt(ctx, pool, params, session),
    "nostr.nip44Decrypt": async (ctx, params, session) =>
      ops.nip44Decrypt(ctx, pool, params, session),
    "nostr.unwrapGiftWraps": async (ctx, params, session) =>
      ops.unwrapGiftWraps(ctx, pool, params, session),
  };

  return {
    vault,
    handlers,
    status: (records) => nostrStatus(records),
  };
}
