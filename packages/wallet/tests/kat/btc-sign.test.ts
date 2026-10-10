import { schnorr } from "@noble/curves/secp256k1.js";
import { bech32m } from "@scure/base";
import { expect, test } from "vite-plus/test";

import { bitcoinMessageDigest, BtcSigner, createBtcDeriver } from "../../src/chains/btc/index.ts";
import { bytesToHex, hexToBytes } from "../../src/crypto/hex.ts";
import { hash256 } from "../../src/crypto/index.ts";
import { walletFromMnemonic } from "../../src/hd/index.ts";
import { SignError, signOutputToHex } from "../../src/sign/index.ts";

const PRIV = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
const ADDRESS = "1FB3WSwtExGLQUmNp4AQF66tAwAQp6igW3";
const MESSAGE = "signer kat v3";
const MESSAGE_DIGEST_HEX = "017bddbdc908e54f74f4c57cda0390adaa23d05b775229a486f7fe6ecdd4902b";
const SIGN_TX_HEX =
  "ea9298254514da415af8f810e618dd08440e24b3e8c9002d46ebd7ebb2bd97fe2a8ddce39abda97c3abddc0017746355be5f32bbf6f236258c3b8cba7e2578a401";
const BIP137_UNCOMPRESSED =
  "7818ef7a410e1f6c7c8a96e7d5bfb7619838b8a015d5c1895c2ac00dea169de23a238e9aefc0748c75c32e832d9e55ff1210ee323be511630690715fd4c883cc1c";
const BIP137_COMPRESSED =
  "7818ef7a410e1f6c7c8a96e7d5bfb7619838b8a015d5c1895c2ac00dea169de23a238e9aefc0748c75c32e832d9e55ff1210ee323be511630690715fd4c883cc20";
const BIP137_P2SH =
  "7818ef7a410e1f6c7c8a96e7d5bfb7619838b8a015d5c1895c2ac00dea169de23a238e9aefc0748c75c32e832d9e55ff1210ee323be511630690715fd4c883cc24";
const BIP137_BECH32 =
  "7818ef7a410e1f6c7c8a96e7d5bfb7619838b8a015d5c1895c2ac00dea169de23a238e9aefc0748c75c32e832d9e55ff1210ee323be511630690715fd4c883cc28";

test("gold: P2PKH identity address", () => {
  using s = BtcSigner.fromHex(PRIV, { network: "mainnet", type: "p2pkh" });
  expect(s.address()).toBe(ADDRESS);
});

test("fromHex address() throws without network and type", () => {
  using s = BtcSigner.fromHex(PRIV);
  expect(() => s.address()).toThrow(SignError);
});

test("gold: BIP-137 message digest", () => {
  expect(bytesToHex(bitcoinMessageDigest(new TextEncoder().encode(MESSAGE)))).toBe(
    MESSAGE_DIGEST_HEX,
  );
});

test("gold: BIP-137 four headers", () => {
  using s = BtcSigner.fromHex(PRIV);
  const msg = new TextEncoder().encode(MESSAGE);
  expect(signOutputToHex(s.signMessageWith("p2pkh-uncompressed", msg))).toBe(BIP137_UNCOMPRESSED);
  expect(signOutputToHex(s.signMessage(msg))).toBe(BIP137_COMPRESSED);
  expect(signOutputToHex(s.signMessageWith("segwit-p2sh", msg))).toBe(BIP137_P2SH);
  expect(signOutputToHex(s.signMessageWith("segwit-bech32", msg))).toBe(BIP137_BECH32);
});

test("gold: sighash signTransaction double-SHA256", () => {
  using s = BtcSigner.fromHex(PRIV);
  const out = s.signTransaction(hexToBytes("deadbeef00010203"));
  expect(signOutputToHex(out)).toBe(SIGN_TX_HEX);
});

test("signDigestDer signs a 32-byte digest without hash256", () => {
  using s = BtcSigner.fromHex(PRIV);
  const preimage = hexToBytes("deadbeef00010203");
  const hashed = hash256(preimage);
  const der = s.signDigestDer(hashed);
  expect(der.scheme).toBe("ecdsa_der");
  if (der.scheme !== "ecdsa_der") {
    throw new Error("expected der");
  }
  expect(der.der[0]).toBe(0x30);
  expect(s.verifyHash(hashed, der.der)).toBe(true);
  const doubleHashed = s.signTransaction(hashed);
  expect(signOutputToHex(doubleHashed)).not.toBe(signOutputToHex(der));
  const fromPreimage = s.signTransaction(preimage);
  expect(fromPreimage.scheme).toBe("ecdsa_recoverable");
  if (fromPreimage.scheme !== "ecdsa_recoverable") {
    throw new Error("expected recoverable");
  }
  expect(s.verifyHash(hashed, fromPreimage.signature)).toBe(true);
});

test("signTaprootKeyPath is BIP-86 Schnorr over 32 bytes", () => {
  const w = walletFromMnemonic(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  );
  using acct = createBtcDeriver(w).deriveWith("p2tr", 0);
  w.dispose();
  using s = BtcSigner.fromDerived(acct);
  const digest = new Uint8Array(32).fill(7);
  const out = s.signTaprootKeyPath(digest);
  expect(out.scheme).toBe("schnorr");
  if (out.scheme !== "schnorr") {
    throw new Error("expected schnorr");
  }
  expect(out.signature).toHaveLength(64);
  expect(schnorr.verify(out.signature, digest, out.xonlyPublicKey)).toBe(true);
  const dec = bech32m.decode(acct.address);
  expect(dec.prefix).toBe("bc");
  expect(dec.words[0]).toBe(1);
  const prog = bech32m.fromWords(dec.words.slice(1));
  expect(bytesToHex(out.xonlyPublicKey)).toBe(bytesToHex(prog));
});

test("BtcSigner.fromDerived from derived account", () => {
  const w = walletFromMnemonic(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  );
  using acct = createBtcDeriver(w).deriveWith("p2pkh", 0);
  w.dispose();
  using s = BtcSigner.fromDerived(acct);
  expect(s.address()).toBe("1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA");
});

test("BtcSigner.fromDerived captures testnet address", () => {
  const w = walletFromMnemonic(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  );
  using acct = createBtcDeriver(w, "testnet").deriveWith("p2wpkh", 0);
  using fromHex = BtcSigner.fromHex(acct.privateKeyHex(), { network: "testnet", type: "p2wpkh" });
  w.dispose();
  using s = BtcSigner.fromDerived(acct);
  expect(s.address()).toBe(acct.address);
  expect(s.address()).toBe("tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl");
  expect(fromHex.address()).toBe(acct.address);
});
