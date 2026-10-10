import { expect, test } from "vitest";
import { aptosPath, createAptosDeriver } from "../../src/chains/aptos/index.ts";
import { walletFromMnemonic } from "../../src/hd/index.ts";

const ABANDON =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

test("gold: Aptos abandon index 0 (kobe-aptos)", () => {
  const w = walletFromMnemonic(ABANDON);
  using a = createAptosDeriver(w).derive(0);
  expect(a.path).toBe("m/44'/637'/0'/0'/0'");
  expect(aptosPath(0)).toBe("m/44'/637'/0'/0'/0'");
  expect(a.address).toBe("0xeb663b681209e7087d681c5d3eed12aaa8e1915e7c87794542c3f96e94b3d3bf");
  expect(a.privateKeyHex()).toBe(
    "cc92c0eaf80206d817f150e21917f797e49cf644a33ac514de3c316baa2f1bf5",
  );
  w.dispose();
});

test("gold: Aptos abandon index 1", () => {
  const w = walletFromMnemonic(ABANDON);
  using a = createAptosDeriver(w).derive(1);
  expect(a.path).toBe("m/44'/637'/1'/0'/0'");
  expect(a.address).toBe("0xf867372dfec13fb6c0740d4b574363685e10e6f243e9554ffa8f6e698e940efa");
  expect(a.privateKeyHex()).toBe(
    "4c6f5a6b687631dd52f32c97457e895fb57947b9b827c6697c11cd7b2a075c5b",
  );
  w.dispose();
});

test("deriveMany matches scalar derive", () => {
  const w = walletFromMnemonic(ABANDON);
  const d = createAptosDeriver(w);
  const batch = d.deriveMany(0, 3);
  for (let i = 0; i < 3; i++) {
    using single = d.derive(i);
    expect(batch[i]!.address).toBe(single.address);
  }
  for (const a of batch) a.dispose();
  w.dispose();
});
