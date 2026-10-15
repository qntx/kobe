import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vite-plus/test";

import { masterKey } from "../src/derive/hd.ts";
import { walletIdOf } from "../src/derive/wallet-id.ts";
import { loadVectors } from "./helpers.ts";

type WalletIdVector = { seed: string; masterPublicKey: string; walletId: string };
const { vectors } = loadVectors("wallet-id.json") as { vectors: WalletIdVector[] };

describe("walletId", () => {
  it.each(vectors)("$seed → $walletId", (vector) => {
    const master = masterKey(hexToBytes(vector.seed));
    expect(bytesToHex(master.publicKey!)).toBe(vector.masterPublicKey);
    expect(walletIdOf(master)).toBe(vector.walletId);
    master.wipePrivateData();
  });
});
