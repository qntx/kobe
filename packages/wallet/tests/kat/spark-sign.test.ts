import { expect, test } from "vitest";
import {
  createSparkDeriver,
  createSparkSigner,
  sparkMessageDigest,
  sparkSignerFromHex,
} from "../../src/chains/spark/index.ts";
import { hexToBytes } from "../../src/crypto/hex.ts";
import { hash256 } from "../../src/crypto/index.ts";
import { walletFromMnemonic } from "../../src/hd/index.ts";
import { signOutputToBytes, signOutputToHex } from "../../src/sign/index.ts";

const PRIV = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
const TX_HEX = "deadbeef00010203";
const MESSAGE = "signer kat v3";
const SIGN_TX_HEX =
  "ea9298254514da415af8f810e618dd08440e24b3e8c9002d46ebd7ebb2bd97fe2a8ddce39abda97c3abddc0017746355be5f32bbf6f236258c3b8cba7e2578a401";
const SIGN_MESSAGE_HEX =
  "7818ef7a410e1f6c7c8a96e7d5bfb7619838b8a015d5c1895c2ac00dea169de23a238e9aefc0748c75c32e832d9e55ff1210ee323be511630690715fd4c883cc20";

test("gold: signTransaction double-SHA256", () => {
  using s = sparkSignerFromHex(PRIV);
  const tx = hexToBytes(TX_HEX);
  const out = s.signTransaction(tx);
  expect(signOutputToHex(out)).toBe(SIGN_TX_HEX);
  if (out.scheme === "ecdsa_recoverable") {
    expect(out.v === 0 || out.v === 1).toBe(true);
  }
  expect(s.verifyHash(hash256(tx), signOutputToBytes(out))).toBe(true);
  expect(s.verifyHash(hash256(tx), signOutputToBytes(out).subarray(0, 64))).toBe(true);
});

test("gold: signMessage BIP-137 compressed P2PKH", () => {
  using s = sparkSignerFromHex(PRIV);
  const out = s.signMessage(new TextEncoder().encode(MESSAGE));
  expect(signOutputToHex(out)).toBe(SIGN_MESSAGE_HEX);
  if (out.scheme === "ecdsa_recoverable") {
    expect(out.v === 31 || out.v === 32).toBe(true);
  }
  expect(
    s.verifyHash(sparkMessageDigest(new TextEncoder().encode(MESSAGE)), signOutputToBytes(out)),
  ).toBe(true);
});

test("verifyHash rejects a flipped bit", () => {
  using s = sparkSignerFromHex(PRIV);
  const tx = hexToBytes(TX_HEX);
  const tampered = signOutputToBytes(s.signTransaction(tx));
  tampered[32] = (tampered[32] ?? 0) ^ 0x01;
  expect(s.verifyHash(hash256(tx), tampered)).toBe(false);
});

test("createSparkSigner from derived account", () => {
  const w = walletFromMnemonic(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  );
  using acct = createSparkDeriver(w).derive(0);
  w.dispose();
  using s = createSparkSigner(acct);
  expect(s.address()).toBe(acct.address);
});
