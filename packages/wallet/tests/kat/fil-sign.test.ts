import { expect, test } from "vitest";
import {
  createFilDeriver,
  createFilSigner,
  filBlake2b256,
  filSignerFromHex,
} from "../../src/chains/fil/index.ts";
import { hexToBytes } from "../../src/crypto/hex.ts";
import { walletFromMnemonic } from "../../src/hd/index.ts";
import { signOutputToBytes, signOutputToHex } from "../../src/sign/index.ts";

const PRIV = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
const ADDRESS = "f1utzlswpqelskilx7nxzz3ocwjrsc3ejwwhooyhq";
const SIGN_TX_HEX =
  "7b30af7ea3acd312a098f62ff59960dd43f8a7bae8b34ddcd7c443dcb568dabb0b8c3f31e5455b58bf61afd1511eb2c60bd06d7c72c5e7261539253093ec813801";

test("gold: Filecoin f1 address from fixture key", () => {
  using s = filSignerFromHex(PRIV);
  expect(s.address()).toBe(ADDRESS);
});

test("gold: signTransaction ECDSA(BLAKE2b-256)", () => {
  using s = filSignerFromHex(PRIV);
  const tx = hexToBytes("deadbeef00010203");
  const out = s.signTransaction(tx);
  expect(signOutputToHex(out)).toBe(SIGN_TX_HEX);
  if (out.scheme === "ecdsa_recoverable") {
    expect(out.v === 0 || out.v === 1).toBe(true);
  }
  expect(s.verifyHash(filBlake2b256(tx), signOutputToBytes(out))).toBe(true);
});

test("verifyHash rejects a flipped bit", () => {
  using s = filSignerFromHex(PRIV);
  const tx = hexToBytes("deadbeef00010203");
  const out = s.signTransaction(tx);
  const tampered = signOutputToBytes(out);
  tampered[0] = (tampered[0] ?? 0) ^ 0x01;
  expect(s.verifyHash(filBlake2b256(tx), tampered)).toBe(false);
});

test("no signMessage", () => {
  using s = filSignerFromHex(PRIV);
  expect("signMessage" in s).toBe(false);
});

test("createFilSigner from derived account", () => {
  const w = walletFromMnemonic(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  );
  using acct = createFilDeriver(w).derive(0);
  w.dispose();
  using s = createFilSigner(acct);
  expect(s.address()).toBe(acct.address);
});
