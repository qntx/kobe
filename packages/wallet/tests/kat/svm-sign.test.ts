import { expect, test } from "vitest";
import {
  createSvmDeriver,
  createSvmSigner,
  svmSignerFromHex,
  svmSignerFromKeypairBase58,
} from "../../src/chains/svm/index.ts";
import { hexToBytes } from "../../src/crypto/hex.ts";
import { walletFromMnemonic } from "../../src/hd/index.ts";
import { SignError, signOutputToBytes } from "../../src/sign/index.ts";

const PRIV = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const ADDRESS = "FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z";
const MESSAGE = "signer kat v3";

test("shape: address is base58(pubkey) RFC 8032 TV1", () => {
  using s = svmSignerFromHex(PRIV);
  expect(s.address()).toBe(ADDRESS);
});

test("shape: signMessage/signTransaction/signDigest self-verify", () => {
  using s = svmSignerFromHex(PRIV);
  const tx = hexToBytes("deadbeef00010203");
  const digest = hexToBytes("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
  const msg = new TextEncoder().encode(MESSAGE);
  const m = s.signMessage(msg);
  const t = s.signTransaction(tx);
  const d = s.signDigest(digest);
  expect(signOutputToBytes(m).length).toBe(64);
  expect(s.verify(msg, signOutputToBytes(m))).toBe(true);
  expect(s.verify(tx, signOutputToBytes(t))).toBe(true);
  expect(s.verify(digest, signOutputToBytes(d))).toBe(true);
});

test("shape: keypairBase58 round-trip", () => {
  using s = svmSignerFromHex(PRIV);
  using via = svmSignerFromKeypairBase58(s.keypairBase58());
  expect(via.address()).toBe(s.address());
});

test("fromKeypairBase58 rejects invalid", () => {
  expect(() => svmSignerFromKeypairBase58("invalid!!!")).toThrow(SignError);
});

test("extractSignableBytes strips compact-u16 + slot", () => {
  using s = svmSignerFromHex(PRIV);
  const body = new TextEncoder().encode("message_body");
  const tx = new Uint8Array(1 + 64 + body.length);
  tx[0] = 1;
  tx.set(body, 65);
  expect(s.extractSignableBytes(tx)).toEqual(body);
  expect(() => s.extractSignableBytes(new Uint8Array(0))).toThrow(SignError);
});

test("encodeSignedTransaction splices first slot", () => {
  using s = svmSignerFromHex(PRIV);
  const body = new TextEncoder().encode("message_body");
  const tx = new Uint8Array(1 + 64 + body.length);
  tx[0] = 1;
  tx.set(body, 65);
  const sig = s.signMessage(body);
  const signed = s.encodeSignedTransaction(tx, sig);
  expect(signed.subarray(1, 65)).toEqual(signOutputToBytes(sig));
  expect(signed.subarray(65)).toEqual(body);
});

test("createSvmSigner from derived account", () => {
  const w = walletFromMnemonic(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  );
  using acct = createSvmDeriver(w).derive(0);
  w.dispose();
  using s = createSvmSigner(acct);
  expect(s.address()).toBe(acct.address);
});
