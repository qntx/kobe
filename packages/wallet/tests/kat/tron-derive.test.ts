import { expect, test } from "vitest";
import { createTronDeriver, tronPath } from "../../src/chains/tron/index.ts";
import { walletFromMnemonic } from "../../src/hd/index.ts";

const ABANDON =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

test("gold: Tron abandon index 0 (kobe-tron)", () => {
  const w = walletFromMnemonic(ABANDON);
  using a = createTronDeriver(w).derive(0);
  expect(a.path).toBe("m/44'/195'/0'/0/0");
  expect(tronPath(0)).toBe("m/44'/195'/0'/0/0");
  expect(a.address).toBe("TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH");
  expect(a.privateKeyHex()).toBe(
    "b5a4cea271ff424d7c31dc12a3e43e401df7a40d7412a15750f3f0b6b5449a28",
  );
  expect(a.publicKey.kind).toBe("secp256k1-uncompressed");
  w.dispose();
});

test("gold: Tron abandon index 1", () => {
  const w = walletFromMnemonic(ABANDON);
  using a = createTronDeriver(w).derive(1);
  expect(a.path).toBe("m/44'/195'/0'/0/1");
  expect(a.address).toBe("TSeJkUh4Qv67VNFwY8LaAxERygNdy6NQZK");
  expect(a.privateKeyHex()).toBe(
    "edb728e259afca2ddcc428459e7681b8414668649aedbc8d25c0872da219b2e6",
  );
  w.dispose();
});

test("deriveMany matches scalar derive", () => {
  const w = walletFromMnemonic(ABANDON);
  const d = createTronDeriver(w);
  const batch = d.deriveMany(0, 3);
  for (let i = 0; i < 3; i++) {
    using single = d.derive(i);
    expect(batch[i]!.address).toBe(single.address);
  }
  for (const a of batch) a.dispose();
  w.dispose();
});

test("passphrase changes address", () => {
  const a = walletFromMnemonic(ABANDON);
  const b = walletFromMnemonic(ABANDON, "TREZOR");
  using aa = createTronDeriver(a).derive(0);
  using bb = createTronDeriver(b).derive(0);
  expect(aa.address).not.toBe(bb.address);
  a.dispose();
  b.dispose();
});
