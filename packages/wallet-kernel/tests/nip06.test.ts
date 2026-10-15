import { schnorr } from "@noble/curves/secp256k1.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { bech32 } from "@scure/base";
import { describe, expect, it } from "vite-plus/test";

import { masterKey } from "../src/derive/hd.ts";
import { nostrKeyAt } from "../src/derive/templates.ts";
import { entropyFromMnemonic } from "../src/seed/mnemonic.ts";
import { seedFromEntropy } from "../src/seed/seed.ts";
import { kernelError, loadVectors, subtlePbkdf2 } from "./helpers.ts";

type Nip06Vector = {
  mnemonic: string;
  privateKey: string;
  publicKey: string;
  nsec: string;
  npub: string;
};
const { vectors } = loadVectors("nip06.json") as { vectors: Nip06Vector[] };

describe("NIP-06 vectors", () => {
  it.each(vectors)("group 0 key for $mnemonic", async (vector) => {
    const seed = await seedFromEntropy(entropyFromMnemonic(vector.mnemonic), subtlePbkdf2);
    const master = masterKey(seed);
    const privateKey = nostrKeyAt(master, 0);
    expect(bytesToHex(privateKey)).toBe(vector.privateKey);
    expect(bytesToHex(schnorr.getPublicKey(privateKey))).toBe(vector.publicKey);
    expect(bech32.encode("nsec", bech32.toWords(privateKey))).toBe(vector.nsec);
    expect(bech32.encode("npub", bech32.toWords(schnorr.getPublicKey(privateKey)))).toBe(
      vector.npub,
    );
    master.wipePrivateData();
  });
});

describe("nostrKeyAt groupIndex bounds", () => {
  it("rejects non-integer and out-of-range indexes", async () => {
    const seed = await seedFromEntropy(entropyFromMnemonic(vectors[0]!.mnemonic), subtlePbkdf2);
    const master = masterKey(seed);
    for (const index of [-1, 2 ** 31, 0.5, Number.NaN]) {
      expect(kernelError(() => nostrKeyAt(master, index))).toBe("invalid-input");
    }
    expect(nostrKeyAt(master, 2 ** 31 - 1)).not.toStrictEqual(nostrKeyAt(master, 0));
    master.wipePrivateData();
  });
});
