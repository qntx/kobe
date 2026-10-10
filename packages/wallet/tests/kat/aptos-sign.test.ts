import { expect, test } from "vitest";
import {
  aptosRawTxDomainHash,
  aptosSignerFromHex,
  aptosTxSigningMessage,
  createAptosDeriver,
  createAptosSigner,
} from "../../src/chains/aptos/index.ts";
import { bytesToHex, hexToBytes } from "../../src/crypto/hex.ts";
import { walletFromMnemonic } from "../../src/hd/index.ts";
import { signOutputPublicKey, signOutputToHex } from "../../src/sign/index.ts";

const PRIV = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const PUBKEY = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const ADDRESS = "0x63c5215e87770d17b9f4cd47c777e322f4eb152cfd2054c1080fd9d57c48913b";
const DOMAIN_HEX = "b5e97db07fa0bd0e5598aa3643a9bc6f6693bddc1a9fec9e674a461eaa00b193";
const SIGN_TX_HEX =
  "b63e642190fb953456a210605d6a72aae8719e974306e9c25d17a4c4d44b412d106b3c261a1a961c0f3121be47b8d02509a1dfac9d45b3a284687ad42c4ac201";

test("gold: Aptos address SHA3-256(pk||0x00)", () => {
  using s = aptosSignerFromHex(PRIV);
  expect(s.publicKeyHex()).toBe(PUBKEY);
  expect(s.address()).toBe(ADDRESS);
});

test("gold: APTOS::RawTransaction domain hash", () => {
  expect(bytesToHex(aptosRawTxDomainHash())).toBe(DOMAIN_HEX);
});

test("gold: signTransaction domain-prefixed Ed25519", () => {
  using s = aptosSignerFromHex(PRIV);
  const tx = hexToBytes("deadbeef00010203");
  const out = s.signTransaction(tx);
  expect(out.scheme).toBe("ed25519_with_pubkey");
  expect(signOutputToHex(out)).toBe(SIGN_TX_HEX);
  expect(bytesToHex(signOutputPublicKey(out)!)).toBe(PUBKEY);
  if (out.scheme === "ed25519_with_pubkey") {
    expect(s.verify(aptosTxSigningMessage(tx), out.signature)).toBe(true);
  }
});

test("signRaw is plain Ed25519; no signMessage", () => {
  using s = aptosSignerFromHex(PRIV);
  const msg = new TextEncoder().encode("signer kat v3");
  const out = s.signRaw(msg);
  expect(out.scheme).toBe("ed25519");
  expect(s.verify(msg, out.scheme === "ed25519" ? out.signature : new Uint8Array())).toBe(true);
  expect("signMessage" in s).toBe(false);
});

test("createAptosSigner from derived account", () => {
  const w = walletFromMnemonic(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  );
  using acct = createAptosDeriver(w).derive(0);
  w.dispose();
  using s = createAptosSigner(acct);
  expect(s.address()).toBe(acct.address);
});
