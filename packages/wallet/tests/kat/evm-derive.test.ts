import { expect, test } from "vitest";
import { createEvmDeriver, evmPath, parseEvmStyle } from "../../src/chains/evm/index.ts";
import { DeriveError, walletFromMnemonic } from "../../src/hd/index.ts";

const ABANDON =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const HARDHAT = "test test test test test test test test test test test junk";

test("gold: Hardhat default index 0", () => {
  const w = walletFromMnemonic(HARDHAT);
  const d = createEvmDeriver(w);
  using a = d.derive(0);
  expect(a.path).toBe("m/44'/60'/0'/0/0");
  expect(a.address).toBe("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
  expect(a.privateKeyHex()).toBe(
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
  );
  expect(a.publicKey.kind).toBe("secp256k1-uncompressed");
  expect(a.publicKey.bytes.length).toBe(65);
  w.dispose();
});

test("gold: Hardhat default index 1", () => {
  const w = walletFromMnemonic(HARDHAT);
  using a = createEvmDeriver(w).derive(1);
  expect(a.path).toBe("m/44'/60'/0'/0/1");
  expect(a.address).toBe("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
  expect(a.privateKeyHex()).toBe(
    "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
  );
  w.dispose();
});

test("gold: abandon index 0 / 1 (kobe-evm)", () => {
  const w = walletFromMnemonic(ABANDON);
  const d = createEvmDeriver(w);
  using a0 = d.derive(0);
  using a1 = d.derive(1);
  expect(a0.address).toBe("0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
  expect(a0.privateKeyHex()).toBe(
    "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727",
  );
  expect(a1.address).toBe("0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0");
  expect(a1.privateKeyHex()).toBe(
    "9a983cb3d832fbde5ab49d692b7a8bf5b5d232479c99333d0fc8e1d21f1b55b6",
  );
  w.dispose();
});

test("style path shapes match kobe", () => {
  expect(evmPath("standard", 0)).toBe("m/44'/60'/0'/0/0");
  expect(evmPath("ledger-live", 1)).toBe("m/44'/60'/1'/0/0");
  expect(evmPath("ledger-legacy", 2)).toBe("m/44'/60'/0'/2");
});

test("parseEvmStyle aliases and rejects unknown", () => {
  expect(parseEvmStyle("MetaMask")).toBe("standard");
  expect(parseEvmStyle("LIVE")).toBe("ledger-live");
  expect(parseEvmStyle("mew")).toBe("ledger-legacy");
  expect(() => parseEvmStyle("definitely-not-a-style")).toThrow(DeriveError);
});

test("styles at index 1 produce distinct addresses", () => {
  const w = walletFromMnemonic(ABANDON);
  const d = createEvmDeriver(w);
  const standard = d.deriveWith("standard", 1);
  const live = d.deriveWith("ledger-live", 1);
  const legacy = d.deriveWith("ledger-legacy", 1);
  expect(standard.path).toBe("m/44'/60'/0'/0/1");
  expect(live.path).toBe("m/44'/60'/1'/0/0");
  expect(legacy.path).toBe("m/44'/60'/0'/1");
  expect(new Set([standard.address, live.address, legacy.address]).size).toBe(3);
  standard.dispose();
  live.dispose();
  legacy.dispose();
  w.dispose();
});

test("deriveMany matches scalar derive", () => {
  const w = walletFromMnemonic(ABANDON);
  const d = createEvmDeriver(w);
  const batch = d.deriveMany(0, 5);
  for (let i = 0; i < 5; i++) {
    using single = d.derive(i);
    expect(batch[i]!.address).toBe(single.address);
    expect(batch[i]!.path).toBe(single.path);
  }
  for (const a of batch) a.dispose();
  w.dispose();
});

test("wallet dispose then derive throws", () => {
  const w = walletFromMnemonic(ABANDON);
  const d = createEvmDeriver(w);
  w.dispose();
  expect(() => d.derive(0)).toThrow(DeriveError);
});
