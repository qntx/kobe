import type { HDKey } from "@scure/bip32";

import { KernelError } from "../errors.ts";

export type TemplateId = "nostr.nip06";

/** `i` is the account-group index segment. Spark and chain templates join in E1/E2. */
export type Template = {
  readonly curve: "secp256k1";
  readonly path: string;
};

export const TEMPLATES: Readonly<Record<TemplateId, Template>> = {
  "nostr.nip06": { curve: "secp256k1", path: "m/44'/1237'/i'/0/0" },
};

/** NIP-06 private key of account group `groupIndex` (m/44'/1237'/i'/0/0). */
export function nostrKeyAt(master: HDKey, groupIndex: number): Uint8Array {
  if (!Number.isSafeInteger(groupIndex) || groupIndex < 0 || groupIndex > 0x7fffffff) {
    throw new KernelError("invalid-input", "group index out of range");
  }
  const path = TEMPLATES["nostr.nip06"].path
    .split("/")
    .map((segment) => (segment === "i'" ? `${groupIndex}'` : segment))
    .join("/");
  const node = master.derive(path);
  try {
    const key = node.privateKey;
    if (key === null || key.length !== 32) {
      throw new KernelError("integrity", "derived node has no private key");
    }
    return Uint8Array.from(key);
  } finally {
    node.wipePrivateData();
  }
}
