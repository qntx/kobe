import { expect, test } from "vitest";
import {
  createTronDeriver,
  createTronSigner,
  tronSignerFromHex,
} from "../../src/chains/tron/index.ts";
import { hexToBytes } from "../../src/crypto/hex.ts";
import { sha256Bytes } from "../../src/crypto/index.ts";
import { walletFromMnemonic } from "../../src/hd/index.ts";
import { signOutputToHex } from "../../src/sign/index.ts";

const PRIV = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
const ADDRESS = "TE2H9hWjzYdwzDFRJfx9BFhr4MmjH1CHaz";
const MESSAGE = "signer kat v3";
const SIGN_TX_HEX =
  "15b8b358ef121aec278447ad105a23c7c157b3be7f6c86a263efecd38449cb5638bb8efbd57a1e47b4c80b5738dfd02d8ea981da11a7e550772448b57a97bc4700";
const SIGN_MESSAGE_HEX =
  "04a06ace4ef7d14d87347a0315fb15b6f42953a3894571bb4cfb15eb8a8a9c5708642994ebd54abc37ed627d5fe5c6748c41561053a1daa8ea2116a75ebf34fe1b";

test("gold: TRON Base58Check address from fixture key", () => {
  using s = tronSignerFromHex(PRIV);
  expect(s.address()).toBe(ADDRESS);
});

test("gold: TRON signMessage prefix + v 27|28", () => {
  using s = tronSignerFromHex(PRIV);
  const out = s.signMessage(new TextEncoder().encode(MESSAGE));
  expect(signOutputToHex(out)).toBe(SIGN_MESSAGE_HEX);
  if (out.scheme === "ecdsa_recoverable") {
    expect(out.v === 27 || out.v === 28).toBe(true);
  }
});

test("gold: TRON signTransaction SHA-256 raw_data", () => {
  using s = tronSignerFromHex(PRIV);
  const tx = hexToBytes("deadbeef00010203");
  const out = s.signTransaction(tx);
  expect(signOutputToHex(out)).toBe(SIGN_TX_HEX);
  if (out.scheme === "ecdsa_recoverable") {
    expect(out.v === 0 || out.v === 1).toBe(true);
  }
  expect(
    s.verifyHash(
      sha256Bytes(tx),
      out.scheme === "ecdsa_recoverable" ? out.signature : new Uint8Array(),
    ),
  ).toBe(true);
});

test("createTronSigner from derived account", () => {
  const w = walletFromMnemonic(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  );
  using acct = createTronDeriver(w).derive(0);
  w.dispose();
  using s = createTronSigner(acct);
  expect(s.address()).toBe(acct.address);
});
