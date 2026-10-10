import { expect, test } from "vitest";
import {
  cosmosSignerFromHex,
  createCosmosDeriver,
  createCosmosSigner,
} from "../../src/chains/cosmos/index.ts";
import { hexToBytes } from "../../src/crypto/hex.ts";
import { sha256Bytes } from "../../src/crypto/index.ts";
import { walletFromMnemonic } from "../../src/hd/index.ts";
import { signOutputToHex } from "../../src/sign/index.ts";

const PRIV = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
const ADDRESS = "cosmos1nduq8yy8h4nr7g9vuuglzklqatmaquq9tztpj8";
const SIGN_TX_HEX =
  "15b8b358ef121aec278447ad105a23c7c157b3be7f6c86a263efecd38449cb5638bb8efbd57a1e47b4c80b5738dfd02d8ea981da11a7e550772448b57a97bc4700";

test("gold: cosmos1 address from fixture key", () => {
  using s = cosmosSignerFromHex(PRIV);
  expect(s.address()).toBe(ADDRESS);
  expect(s.addressWithHrp("cosmos")).toBe(ADDRESS);
});

test("addressWithHrp covers major HRPs", () => {
  using s = cosmosSignerFromHex(PRIV);
  for (const hrp of ["cosmos", "osmo", "juno", "terra", "secret", "kava"]) {
    const addr = s.addressWithHrp(hrp);
    expect(addr.startsWith(`${hrp}1`)).toBe(true);
  }
  expect(() => s.addressWithHrp("")).toThrow();
});

test("gold: signTransaction SHA-256 SignDoc", () => {
  using s = cosmosSignerFromHex(PRIV);
  const tx = hexToBytes("deadbeef00010203");
  const out = s.signTransaction(tx);
  expect(signOutputToHex(out)).toBe(SIGN_TX_HEX);
  if (out.scheme === "ecdsa_recoverable") {
    expect(out.v === 0 || out.v === 1).toBe(true);
    expect(s.verifyHash(sha256Bytes(tx), out.signature)).toBe(true);
  }
  expect("signMessage" in s).toBe(false);
});

test("createCosmosSigner from derived account", () => {
  const w = walletFromMnemonic(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  );
  using acct = createCosmosDeriver(w).derive(0);
  w.dispose();
  using s = createCosmosSigner(acct);
  expect(s.address()).toBe(acct.address);
});
