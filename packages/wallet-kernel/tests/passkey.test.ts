import { schnorr } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vite-plus/test";

import { masterKey } from "../src/derive/hd.ts";
import { nostrKeyAt } from "../src/derive/templates.ts";
import { walletIdOf } from "../src/derive/wallet-id.ts";
import { KernelError } from "../src/errors.ts";
import { mnemonicFromEntropy } from "../src/seed/mnemonic.ts";
import { entropyFromPrf } from "../src/seed/passkey.ts";
import { seedFromEntropy } from "../src/seed/seed.ts";
import { kernelError, loadVectors, subtlePbkdf2 } from "./helpers.ts";

type PasskeyVector = {
  prf: string;
  entropy: string;
  mnemonic: string;
  seed: string;
  masterPublicKey: string;
  groupIndex: number;
  privateKey: string;
  publicKey: string;
  walletId: string;
};
const { vector } = loadVectors("passkey.json") as { vector: PasskeyVector };

describe("entropyFromPrf", () => {
  it("takes the first 16 bytes and wipes the input", () => {
    const prf = hexToBytes(vector.prf);
    const entropy = entropyFromPrf(prf);
    expect(bytesToHex(entropy)).toBe(vector.entropy);
    expect(prf.every((b) => b === 0)).toBe(true);
  });

  it("rejects a PRF that is not 32 bytes", () => {
    expect(() => entropyFromPrf(new Uint8Array(16))).toThrow(KernelError);
    expect(kernelError(() => entropyFromPrf(new Uint8Array(16)))).toBe("invalid-input");
  });
});

describe("passkey wallet vector", () => {
  it("mnemonic → seed → NIP-06 key → walletId", async () => {
    const entropy = entropyFromPrf(hexToBytes(vector.prf));
    expect(mnemonicFromEntropy(entropy)).toBe(vector.mnemonic);
    const seed = await seedFromEntropy(entropy, subtlePbkdf2);
    expect(bytesToHex(seed)).toBe(vector.seed);
    const master = masterKey(seed);
    expect(bytesToHex(master.publicKey!)).toBe(vector.masterPublicKey);
    const privateKey = nostrKeyAt(master, vector.groupIndex);
    expect(bytesToHex(privateKey)).toBe(vector.privateKey);
    expect(bytesToHex(schnorr.getPublicKey(privateKey))).toBe(vector.publicKey);
    expect(walletIdOf(master)).toBe(vector.walletId);
    master.wipePrivateData();
  });
});
