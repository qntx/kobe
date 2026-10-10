import { expect, test } from "vitest";
import { createXrplDeriver, xrplPath } from "../../src/chains/xrpl/index.ts";
import { walletFromMnemonic } from "../../src/hd/index.ts";

const ABANDON =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

test("gold: XRPL abandon index 0 (kobe-xrpl)", () => {
  const w = walletFromMnemonic(ABANDON);
  using a = createXrplDeriver(w).derive(0);
  expect(a.path).toBe("m/44'/144'/0'/0/0");
  expect(xrplPath(0)).toBe("m/44'/144'/0'/0/0");
  expect(a.address).toBe("rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v3");
  expect(a.privateKeyHex()).toBe(
    "90802a50aa84efb6cdb225f17c27616ea94048c179142fecf03f4712a07ea7a4",
  );
  expect(a.publicKey.kind).toBe("secp256k1-compressed");
  w.dispose();
});

test("gold: XRPL abandon index 1", () => {
  const w = walletFromMnemonic(ABANDON);
  using a = createXrplDeriver(w).derive(1);
  expect(a.path).toBe("m/44'/144'/0'/0/1");
  expect(a.address).toBe("r3AgF9mMBFtaLhKcg96weMhbbEFLZ3mx17");
  expect(a.privateKeyHex()).toBe(
    "0974b4cfe004a2e6c4364cbf3510a36a352796728d0861f6b555ed7e54a70389",
  );
  w.dispose();
});

test("deriveMany matches scalar derive", () => {
  const w = walletFromMnemonic(ABANDON);
  const d = createXrplDeriver(w);
  const batch = d.deriveMany(0, 3);
  for (let i = 0; i < 3; i++) {
    using single = d.derive(i);
    expect(batch[i]!.address).toBe(single.address);
    expect(batch[i]!.path).toBe(single.path);
  }
  for (const a of batch) a.dispose();
  w.dispose();
});

test("passphrase changes address", () => {
  const a = walletFromMnemonic(ABANDON);
  const b = walletFromMnemonic(ABANDON, "TREZOR");
  using aa = createXrplDeriver(a).derive(0);
  using bb = createXrplDeriver(b).derive(0);
  expect(aa.address).not.toBe(bb.address);
  a.dispose();
  b.dispose();
});

test("deriveAt honours account segment", () => {
  const w = walletFromMnemonic(ABANDON);
  using def = createXrplDeriver(w).derive(0);
  using alt = createXrplDeriver(w).deriveAt("m/44'/144'/1'/0/0");
  expect(alt.path).toBe("m/44'/144'/1'/0/0");
  expect(alt.address).not.toBe(def.address);
  w.dispose();
});
