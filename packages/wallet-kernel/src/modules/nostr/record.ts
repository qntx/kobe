import type { NostrKeyInfo } from "@qntx/wallet/types";

import {
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
      readonly origin: "nsec" | "ncryptsec" | "generated" | "nip46-client";
      readonly createdAt: number;
    };

export function encodeNostrKeyHeader(header: NostrKeyHeader): string {
  return header.origin === "derived"
    ? JSON.stringify({
        publicKey: header.publicKey,
        origin: header.origin,
        walletId: header.walletId,
        groupIndex: header.groupIndex,
        createdAt: header.createdAt,
      })
    : JSON.stringify({
        publicKey: header.publicKey,
        origin: header.origin,
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
  expectKeys(object, ["publicKey", "origin", "createdAt"]);
  const { origin } = object;
  if (
    origin !== "nsec" &&
    origin !== "ncryptsec" &&
    origin !== "generated" &&
    origin !== "nip46-client"
  ) {
    throw headerFailure();
  }
  return { publicKey, origin, createdAt };
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
