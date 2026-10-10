import { expect, test } from "vitest";
import { bytesToHex, hexToBytes } from "../../src/crypto/hex.ts";
import {
  ed25519SignerFromSecret,
  secretKeyFromHex,
  signOutputToHex,
} from "../../src/sign/index.ts";

// RFC 8032 §7.1 Test 1 — empty message
const TV1_SK = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const TV1_PK = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const TV1_SIG =
  "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

test("gold: RFC 8032 TV1 empty message", () => {
  using key = secretKeyFromHex(TV1_SK);
  using signer = ed25519SignerFromSecret(key);
  expect(bytesToHex(signer.publicKey())).toBe(TV1_PK);
  const out = signer.sign(new Uint8Array(0));
  expect(out.scheme).toBe("ed25519");
  expect(signOutputToHex(out)).toBe(TV1_SIG);
  expect(signer.verify(new Uint8Array(0), out.signature)).toBe(true);
});

test("gold: RFC 8032 TV2 single-byte 0x72", () => {
  using key = secretKeyFromHex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
  using signer = ed25519SignerFromSecret(key);
  const msg = hexToBytes("72");
  const out = signer.sign(msg);
  expect(signOutputToHex(out)).toBe(
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
  );
  expect(signer.verify(msg, out.signature)).toBe(true);
});
