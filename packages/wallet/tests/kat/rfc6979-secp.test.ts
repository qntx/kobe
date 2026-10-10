import { expect, test } from "vitest";
import { hexToBytes } from "../../src/crypto/hex.ts";
import {
  secp256k1SignerFromSecret,
  secretKeyFromHex,
  signOutputToHex,
} from "../../src/sign/index.ts";

// Pinned against signer-primitives + @noble/curves (lowS).
const KEY_HEX = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
const DIGEST_HEX = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
const SIG_HEX =
  "68597f9553ac0acc453b5a75af2c731e3ca14dbfeae2231123fd202765b12738247bc920ef3e3ceebbc865651f98dc26a25a0d63240c5da091863fe0296e389b00";

test("gold: RFC 6979-style deterministic recoverable ECDSA vs noble", () => {
  using key = secretKeyFromHex(KEY_HEX);
  using signer = secp256k1SignerFromSecret(key);
  const digest = hexToBytes(DIGEST_HEX);
  const out = signer.signPrehashRecoverable(digest);
  expect(out.scheme).toBe("ecdsa_recoverable");
  expect(out.v === 0 || out.v === 1).toBe(true);
  expect(signOutputToHex(out)).toBe(SIG_HEX);
  expect(signer.verifyPrehash(digest, out.signature)).toBe(true);
});
