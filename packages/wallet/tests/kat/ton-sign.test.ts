import { expect, test } from "vitest";
import { createTonDeriver, createTonSigner, tonSignerFromHex } from "../../src/chains/ton/index.ts";
import { hexToBytes } from "../../src/crypto/hex.ts";
import { walletFromMnemonic } from "../../src/hd/index.ts";
import { signOutputPublicKey, signOutputToBytes, signOutputV } from "../../src/sign/index.ts";

const PRIV = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const PUBKEY = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

test("identity is hex public key (not a wallet address)", () => {
  using s = tonSignerFromHex(PRIV);
  expect(s.publicKeyHex()).toBe(PUBKEY);
  expect(s.identity()).toBe(PUBKEY);
  expect("address" in s).toBe(false);
});

test("every entry point is raw Ed25519 and self-verifies", () => {
  using s = tonSignerFromHex(PRIV);
  const digest = new Uint8Array(32).fill(1);
  const tx = hexToBytes("deadbeef00010203");

  const digestOut = s.signDigest(digest);
  const txOut = s.signTransaction(tx);
  const rawOut = s.signRaw(tx);

  for (const [label, payload, out] of [
    ["signDigest", digest, digestOut],
    ["signTransaction", tx, txOut],
    ["signRaw", tx, rawOut],
  ] as const) {
    expect(out.scheme, label).toBe("ed25519");
    expect(signOutputToBytes(out).length, label).toBe(64);
    expect(signOutputV(out), label).toBeUndefined();
    expect(signOutputPublicKey(out), label).toBeUndefined();
    expect(s.verify(payload, signOutputToBytes(out)), label).toBe(true);
  }

  expect(signOutputToBytes(txOut)).toEqual(signOutputToBytes(rawOut));
  expect("signMessage" in s).toBe(false);
});

test("createTonSigner from derived account matches identity", () => {
  const w = walletFromMnemonic(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  );
  using acct = createTonDeriver(w).derive(0);
  w.dispose();
  using s = createTonSigner(acct);
  expect(s.identity()).toBe(acct.publicKeyHex());
  expect(s.identity()).not.toBe(acct.address);
});
