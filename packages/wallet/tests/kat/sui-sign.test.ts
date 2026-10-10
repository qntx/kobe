import { expect, test } from "vitest";
import {
  bcsSerializeBytes,
  createSuiDeriver,
  createSuiSigner,
  suiSignerFromHex,
} from "../../src/chains/sui/index.ts";
import { bytesToHex, hexToBytes } from "../../src/crypto/hex.ts";
import { walletFromMnemonic } from "../../src/hd/index.ts";
import { signOutputPublicKey, signOutputToHex } from "../../src/sign/index.ts";

const PRIV = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const PUBKEY = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const ADDRESS = "0x304af458e90e97c841685b8cbbc59b909f3e2cf150df590ada4c81452c29737d";
const MESSAGE = "signer kat v3";
const BCS_MESSAGE_HEX = "0d7369676e6572206b6174207633";
const SIGN_MESSAGE_HEX =
  "3604fe0b3d39f0f5445e428ee47e1ddfa1a20f03932de0b8fd419a2993cc9555fe61b88e7cd6c97f1127704aadf95cd8ff3b473a08c686d8c02becd9fe162e07";
const SIGN_TX_HEX =
  "e69ae7d37cdc0b67dd79da34d2562f7077aeefc1a5084c547d5d245caee6217c21d497ce2521f28b4ef8a81a4f07bdc5a586017248b52e0e306ea899f5354808";

test("gold: Sui address BLAKE2b-256(flag||pk)", () => {
  using s = suiSignerFromHex(PRIV);
  expect(s.publicKeyHex()).toBe(PUBKEY);
  expect(s.address()).toBe(ADDRESS);
});

test("gold: BCS ULEB128 framing", () => {
  expect(bytesToHex(bcsSerializeBytes(new TextEncoder().encode(MESSAGE)))).toBe(BCS_MESSAGE_HEX);
  const m127 = bcsSerializeBytes(new Uint8Array(127));
  expect(m127[0]).toBe(127);
  expect(m127.length).toBe(128);
  const m128 = bcsSerializeBytes(new Uint8Array(128));
  expect(m128[0]).toBe(0x80);
  expect(m128[1]).toBe(0x01);
  expect(m128.length).toBe(130);
});

test("gold: PersonalMessage intent sign", () => {
  using s = suiSignerFromHex(PRIV);
  const out = s.signMessage(new TextEncoder().encode(MESSAGE));
  expect(out.scheme).toBe("ed25519_with_pubkey");
  expect(signOutputToHex(out)).toBe(SIGN_MESSAGE_HEX);
  expect(bytesToHex(signOutputPublicKey(out)!)).toBe(PUBKEY);
});

test("gold: TransactionData intent sign", () => {
  using s = suiSignerFromHex(PRIV);
  const out = s.signTransaction(hexToBytes("deadbeef00010203"));
  expect(signOutputToHex(out)).toBe(SIGN_TX_HEX);
});

test("encodeSignature is 97-byte flag||sig||pk", () => {
  using s = suiSignerFromHex(PRIV);
  const out = s.signMessage(new TextEncoder().encode("data"));
  const wire = s.encodeSignature(
    out.scheme === "ed25519_with_pubkey" ? out.signature : new Uint8Array(64),
  );
  expect(wire.length).toBe(97);
  expect(wire[0]).toBe(0x00);
  expect(wire.subarray(65)).toEqual(s.publicKeyBytes());
});

test("createSuiSigner from derived account", () => {
  const w = walletFromMnemonic(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  );
  using acct = createSuiDeriver(w).derive(0);
  w.dispose();
  using s = createSuiSigner(acct);
  expect(s.address()).toBe(acct.address);
});
