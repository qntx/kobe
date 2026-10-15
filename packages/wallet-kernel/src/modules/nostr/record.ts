import type { NostrKeyInfo } from "@qntx/wallet/types";

import {
  asBoolean,
  asCreatedAt,
  asGroupIndex,
  asPublicKey,
  asWalletId,
  expectKeys,
  headerFailure,
  headerObject,
} from "../../vault/header-codec.ts";
import type { StoredRecord } from "../../vault/store.ts";

/** The record kind this module owns: one sealed nostr secret key per record, keyed by public key. */
export const NOSTR_KEY_KIND = "nostr-key";

/**
 * `backedUp` exists only on standalone keys (nsec/ncryptsec/generated): they have no parent wallet
 * to recover from, so the header tracks whether the user has exported the key. Derived and
 * nip46-client headers must not carry it.
 */
export type NostrKeyHeader =
  | {
      readonly publicKey: string; // 64 lowercase hex
      readonly origin: "derived";
      readonly walletId: string;
      readonly groupIndex: number;
      readonly createdAt: number;
    }
  | {
      readonly publicKey: string;
      readonly origin: "nsec" | "ncryptsec" | "generated";
      readonly backedUp: boolean;
      readonly createdAt: number;
    }
  | {
      readonly publicKey: string;
      readonly origin: "nip46-client";
      readonly createdAt: number;
    };

export function encodeNostrKeyHeader(header: NostrKeyHeader): string {
  if (header.origin === "derived") {
    return JSON.stringify({
      publicKey: header.publicKey,
      origin: header.origin,
      walletId: header.walletId,
      groupIndex: header.groupIndex,
      createdAt: header.createdAt,
    });
  }
  return header.origin === "nip46-client"
    ? JSON.stringify({
        publicKey: header.publicKey,
        origin: header.origin,
        createdAt: header.createdAt,
      })
    : JSON.stringify({
        publicKey: header.publicKey,
        origin: header.origin,
        backedUp: header.backedUp,
        createdAt: header.createdAt,
      });
}

export function parseNostrKeyHeader(text: string): NostrKeyHeader {
  const object = headerObject(text);
  const publicKey = asPublicKey(object["publicKey"]);
  const createdAt = asCreatedAt(object["createdAt"]);
  if (object["origin"] === "derived") {
    expectKeys(object, ["publicKey", "origin", "walletId", "groupIndex", "createdAt"]);
    return {
      publicKey,
      origin: "derived",
      walletId: asWalletId(object["walletId"]),
      groupIndex: asGroupIndex(object["groupIndex"]),
      createdAt,
    };
  }
  if (object["origin"] === "nip46-client") {
    expectKeys(object, ["publicKey", "origin", "createdAt"]);
    return { publicKey, origin: "nip46-client", createdAt };
  }
  expectKeys(object, ["publicKey", "origin", "backedUp", "createdAt"]);
  const { origin } = object;
  if (origin !== "nsec" && origin !== "ncryptsec" && origin !== "generated") {
    throw headerFailure();
  }
  return { publicKey, origin, backedUp: asBoolean(object["backedUp"]), createdAt };
}

/** The `NostrKeyInfo` a nostr-key record's public header reports. */
export function nostrKeyInfo(header: NostrKeyHeader): NostrKeyInfo {
  const standalone = header.origin !== "derived" && header.origin !== "nip46-client";
  return {
    ref:
      header.origin === "derived"
        ? { kind: "derived", walletId: header.walletId, groupIndex: header.groupIndex }
        : header.origin === "nip46-client"
          ? { kind: "nip46-client", id: header.publicKey }
          : { kind: "standalone", id: header.publicKey },
    publicKey: header.publicKey,
    origin: header.origin,
    ...(standalone ? { backedUp: header.backedUp } : {}),
    createdAt: header.createdAt,
  };
}

/**
 * The module's status section over the records it owns. A record whose header fails the strict
 * parser reports `corrupted` — the row is never silently dropped.
 */
export function nostrStatus(records: ReadonlyArray<StoredRecord>): {
  readonly keys: ReadonlyArray<NostrKeyInfo>;
  readonly corrupted: boolean;
} {
  const keys: NostrKeyInfo[] = [];
  let corrupted = false;
  for (const record of records) {
    try {
      keys.push(nostrKeyInfo(parseNostrKeyHeader(record.header)));
    } catch {
      corrupted = true;
    }
  }
  return { keys, corrupted };
}
