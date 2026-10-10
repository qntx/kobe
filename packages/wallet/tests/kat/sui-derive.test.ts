import { expect, test } from "vitest";
import { createSuiDeriver, suiPath } from "../../src/chains/sui/index.ts";
import { walletFromMnemonic } from "../../src/hd/index.ts";

const ABANDON =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

test("gold: Sui abandon index 0 (kobe-sui)", () => {
  const w = walletFromMnemonic(ABANDON);
  using a = createSuiDeriver(w).derive(0);
  expect(a.path).toBe("m/44'/784'/0'/0'/0'");
  expect(suiPath(0)).toBe("m/44'/784'/0'/0'/0'");
  expect(a.address).toBe("0x5e93a736d04fbb25737aa40bee40171ef79f65fae833749e3c089fe7cc2161f1");
  expect(a.privateKeyHex()).toBe(
    "8869cb07178bf67e08d7c4abdf45487dbf379c9a452fcec2836854bf4a3d29b0",
  );
  w.dispose();
});

test("gold: Sui abandon index 1", () => {
  const w = walletFromMnemonic(ABANDON);
  using a = createSuiDeriver(w).derive(1);
  expect(a.path).toBe("m/44'/784'/1'/0'/0'");
  expect(a.address).toBe("0x082d099250999ab8450a9ef3a962edf9e2449e1045be32ba5a0f2c6117ff7167");
  expect(a.privateKeyHex()).toBe(
    "72613d6091bf9d0b2a9b28e8a18b1de1d527fa60ab2656c5905e92431c98b918",
  );
  w.dispose();
});

test("deriveMany matches scalar derive", () => {
  const w = walletFromMnemonic(ABANDON);
  const d = createSuiDeriver(w);
  const batch = d.deriveMany(0, 3);
  for (let i = 0; i < 3; i++) {
    using single = d.derive(i);
    expect(batch[i]!.address).toBe(single.address);
  }
  for (const a of batch) a.dispose();
  w.dispose();
});
