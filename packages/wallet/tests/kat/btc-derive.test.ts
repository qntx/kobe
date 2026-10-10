import { inspect } from "node:util";
import { expect, test } from "vitest";
import { createBtcDeriver } from "../../src/chains/btc/index.ts";
import { walletFromMnemonic } from "../../src/hd/index.ts";

const ABANDON =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

test("gold: BIP-84 P2WPKH abandon index 0 / 1", () => {
  const w = walletFromMnemonic(ABANDON);
  const d = createBtcDeriver(w, "mainnet");
  using a0 = d.derive(0);
  using a1 = d.deriveWith("p2wpkh", 1);
  expect(a0.path).toBe("m/84'/0'/0'/0/0");
  expect(a0.address).toBe("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
  expect(a0.privateKeyHex()).toBe(
    "4604b4b710fe91f584fff084e1a9159fe4f8408fff380596a604948474ce4fa3",
  );
  expect(a0.addressType()).toBe("p2wpkh");
  expect(a1.address).toBe("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g");
  w.dispose();
});

test("gold: BIP-44 P2PKH abandon index 0", () => {
  const w = walletFromMnemonic(ABANDON);
  using a = createBtcDeriver(w).deriveWith("p2pkh", 0);
  expect(a.path).toBe("m/44'/0'/0'/0/0");
  expect(a.address).toBe("1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA");
  w.dispose();
});

test("gold: BIP-49 P2SH-P2WPKH abandon index 0", () => {
  const w = walletFromMnemonic(ABANDON);
  using a = createBtcDeriver(w).deriveWith("p2sh-p2wpkh", 0);
  expect(a.path).toBe("m/49'/0'/0'/0/0");
  expect(a.address).toBe("37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf");
  w.dispose();
});

test("gold: BIP-86 P2TR abandon index 0 / 1", () => {
  const w = walletFromMnemonic(ABANDON);
  const d = createBtcDeriver(w);
  using a0 = d.deriveWith("p2tr", 0);
  using a1 = d.deriveWith("p2tr", 1);
  expect(a0.path).toBe("m/86'/0'/0'/0/0");
  expect(a0.address).toBe("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr");
  expect(a1.address).toBe("bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh");
  w.dispose();
});

test("gold: testnet P2PKH / P2WPKH / BIP-49", () => {
  const w = walletFromMnemonic(ABANDON);
  const d = createBtcDeriver(w, "testnet");
  using pkh = d.deriveWith("p2pkh", 0);
  using wpkh = d.deriveWith("p2wpkh", 0);
  using sh = d.deriveWith("p2sh-p2wpkh", 0);
  expect(pkh.address).toBe("mkpZhYtJu2r87Js3pDiWJDmPte2NRZ8bJV");
  expect(wpkh.address).toBe("tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl");
  expect(sh.address).toBe("2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2");
  w.dispose();
});

test("WIF redacted after inspect; throws after dispose", () => {
  const w = walletFromMnemonic(ABANDON);
  const a = createBtcDeriver(w).derive(0);
  const wif = a.privateKeyWif();
  expect(wif.startsWith("L") || wif.startsWith("K")).toBe(true);
  expect(inspect(a)).toContain("[REDACTED]");
  expect(inspect(a)).not.toContain(wif);
  a.dispose();
  expect(() => a.privateKeyWif()).toThrow();
  w.dispose();
});
