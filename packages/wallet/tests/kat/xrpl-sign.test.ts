import { expect, test } from "vitest";
import {
  createXrplDeriver,
  createXrplSigner,
  xrplSignerFromHex,
  xrplTxDigest,
} from "../../src/chains/xrpl/index.ts";
import { hexToBytes } from "../../src/crypto/hex.ts";
import { walletFromMnemonic } from "../../src/hd/index.ts";
import {
  SignError,
  signOutputToBytes,
  signOutputToHex,
  signOutputV,
} from "../../src/sign/index.ts";

const PRIV = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
const ADDRESS = "rEBsWSAtNxGLQ7m4FhwQEaatwAwQFa5gWs";
const SIGN_TX_DER_HEX =
  "304402202b6c87da47fe0beadfc837cc15c4997a1945f3e0e89245358c450d658f5c23260220429460ddc1584ded32d0399a0a0d9c1966a1ce19683069b32db100499cbb6a60";

test("gold: XRPL classic r-address from fixture key", () => {
  using s = xrplSignerFromHex(PRIV);
  expect(s.address()).toBe(ADDRESS);
});

test("gold: signTransaction STX + SHA-512-half DER", () => {
  using s = xrplSignerFromHex(PRIV);
  const tx = hexToBytes("deadbeef00010203");
  const out = s.signTransaction(tx);
  expect(out.scheme).toBe("ecdsa_der");
  expect(signOutputToHex(out)).toBe(SIGN_TX_DER_HEX);
  expect(signOutputV(out)).toBeUndefined();
  const bytes = signOutputToBytes(out);
  expect(bytes[0]).toBe(0x30);
  expect(bytes.length).toBeGreaterThanOrEqual(68);
  expect(bytes.length).toBeLessThanOrEqual(72);
  expect(s.verifyHashDer(xrplTxDigest(tx), bytes)).toBe(true);
});

test("verifyHashDer rejects a flipped DER byte", () => {
  using s = xrplSignerFromHex(PRIV);
  const tx = hexToBytes("deadbeef00010203");
  const tampered = signOutputToBytes(s.signTransaction(tx));
  tampered[5] = (tampered[5] ?? 0) ^ 0x01;
  expect(s.verifyHashDer(xrplTxDigest(tx), tampered)).toBe(false);
});

test("signTransaction rejects empty input", () => {
  using s = xrplSignerFromHex(PRIV);
  expect(() => s.signTransaction(new Uint8Array())).toThrow(SignError);
});

test("no signMessage", () => {
  using s = xrplSignerFromHex(PRIV);
  expect("signMessage" in s).toBe(false);
});

test("createXrplSigner from derived account", () => {
  const w = walletFromMnemonic(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  );
  using acct = createXrplDeriver(w).derive(0);
  w.dispose();
  using s = createXrplSigner(acct);
  expect(s.address()).toBe(acct.address);
});
