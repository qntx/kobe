import { sha384 } from "@noble/hashes/sha2.js";
import { SignError } from "../../errors/sign.ts";
import { DEEP_HASH_LEN } from "./address.ts";

export type DeepHashItem =
  | { readonly kind: "blob"; readonly data: Uint8Array }
  | { readonly kind: "list"; readonly items: readonly DeepHashItem[] };

export function deepHashBlob(data: Uint8Array): DeepHashItem {
  return { kind: "blob", data };
}

export function deepHashListItems(items: readonly DeepHashItem[]): DeepHashItem {
  return { kind: "list", items };
}

function sha384_48(data: Uint8Array): Uint8Array {
  return sha384(data);
}

function taggedLenPrefix(kind: string, len: number): Uint8Array {
  return new TextEncoder().encode(`${kind}${len}`);
}

function deepHashBlobBytes(data: Uint8Array): Uint8Array {
  const tagH = sha384_48(taggedLenPrefix("blob", data.length));
  const dataH = sha384_48(data);
  const pair = new Uint8Array(DEEP_HASH_LEN * 2);
  pair.set(tagH, 0);
  pair.set(dataH, DEEP_HASH_LEN);
  return sha384_48(pair);
}

/** Recursive SHA-384 deep-hash. Output is always 48 bytes. */
export function deepHash(item: DeepHashItem): Uint8Array {
  return item.kind === "blob" ? deepHashBlobBytes(item.data) : deepHashList(item.items);
}

export function deepHashList(items: readonly DeepHashItem[]): Uint8Array {
  let acc = sha384_48(taggedLenPrefix("list", items.length));
  for (const child of items) {
    const childHash = deepHash(child);
    const pair = new Uint8Array(DEEP_HASH_LEN * 2);
    pair.set(acc, 0);
    pair.set(childHash, DEEP_HASH_LEN);
    acc = sha384_48(pair);
  }
  return acc;
}

export interface Format2EcdsaFields {
  readonly format: number;
  readonly target: Uint8Array;
  readonly quantity: string;
  readonly reward: string;
  readonly lastTx: Uint8Array;
  readonly tags: ReadonlyArray<readonly [Uint8Array, Uint8Array]>;
  readonly dataSize: number;
  readonly dataRoot: Uint8Array;
}

/** 48-byte deep-hash preimage for ECDSA format=2 (owner omitted). */
export function signatureDataSegmentV2Ecdsa(fields: Format2EcdsaFields): Uint8Array {
  const tagItems: DeepHashItem[] = fields.tags.map(([n, v]) =>
    deepHashListItems([deepHashBlob(n), deepHashBlob(v)]),
  );
  return deepHashList([
    deepHashBlob(new TextEncoder().encode(String(fields.format))),
    deepHashBlob(fields.target),
    deepHashBlob(new TextEncoder().encode(fields.quantity)),
    deepHashBlob(new TextEncoder().encode(fields.reward)),
    deepHashBlob(fields.lastTx),
    deepHashListItems(tagItems),
    deepHashBlob(new TextEncoder().encode(String(fields.dataSize))),
    deepHashBlob(fields.dataRoot),
  ]);
}

export function assertFormat2(fields: Format2EcdsaFields): void {
  if (fields.format !== 2) {
    throw new SignError("invalid_transaction", "Arweave ECDSA requires format=2");
  }
}
