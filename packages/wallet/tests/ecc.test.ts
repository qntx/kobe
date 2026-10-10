import { expect, test } from "vitest";
import {
  ed25519PublicKey,
  ed25519Sign,
  ed25519Verify,
  isValidEd25519Secret,
  isValidSecp256k1Secret,
  secp256k1PublicKey,
  secp256k1SignPrehash,
  secp256k1SignPrehashDer,
  secp256k1VerifyPrehash,
  secp256k1VerifyPrehashDer,
} from "../src/ecc/index.ts";
import { SignError } from "../src/sign/index.ts";
import { sha256Bytes } from "../src/crypto/index.ts";

// Fixed non-zero scalar for deterministic tests (not a real wallet key).
const SECP_SK = Uint8Array.from({ length: 32 }, (_, i) => (i === 31 ? 1 : 0));
const ED_SK = Uint8Array.from({ length: 32 }, (_, i) => i + 1);

test("secp256k1 rejects zero scalar", () => {
  expect(isValidSecp256k1Secret(new Uint8Array(32))).toBe(false);
});

test("secp256k1 rejects wrong length", () => {
  expect(isValidSecp256k1Secret(new Uint8Array(31))).toBe(false);
});

test("secp256k1 public key compressed/uncompressed lengths", () => {
  const c = secp256k1PublicKey(SECP_SK, true);
  const u = secp256k1PublicKey(SECP_SK, false);
  expect(c.length).toBe(33);
  expect(c[0]).toBe(0x02 | (c[0]! & 1)); // 0x02 or 0x03
  expect(u.length).toBe(65);
  expect(u[0]).toBe(0x04);
});

test("secp256k1 sign/verify prehash round-trip", () => {
  const digest = sha256Bytes(new TextEncoder().encode("hello"));
  const { signature, recovery } = secp256k1SignPrehash(SECP_SK, digest);
  expect(signature.length).toBe(64);
  expect(recovery === 0 || recovery === 1).toBe(true);
  const pub = secp256k1PublicKey(SECP_SK, true);
  expect(secp256k1VerifyPrehash(pub, digest, signature)).toBe(true);
});

test("secp256k1 DER sign/verify prehash round-trip", () => {
  const digest = sha256Bytes(new TextEncoder().encode("hello"));
  const der = secp256k1SignPrehashDer(SECP_SK, digest);
  expect(der[0]).toBe(0x30);
  const pub = secp256k1PublicKey(SECP_SK, true);
  expect(secp256k1VerifyPrehashDer(pub, digest, der)).toBe(true);
  expect(() => secp256k1VerifyPrehashDer(pub, digest, der.subarray(0, 4))).toThrow(SignError);
});

test("secp256k1 invalid digest length throws", () => {
  expect(() => secp256k1SignPrehash(SECP_SK, new Uint8Array(31))).toThrow(SignError);
});

test("ed25519 accepts any 32-byte seed", () => {
  expect(isValidEd25519Secret(ED_SK)).toBe(true);
  expect(isValidEd25519Secret(new Uint8Array(31))).toBe(false);
});

test("ed25519 sign/verify round-trip", () => {
  const msg = new TextEncoder().encode("svm-message");
  const pub = ed25519PublicKey(ED_SK);
  expect(pub.length).toBe(32);
  const sig = ed25519Sign(ED_SK, msg);
  expect(sig.length).toBe(64);
  expect(ed25519Verify(pub, msg, sig)).toBe(true);
});

test("ed25519 wrong signature length throws", () => {
  const pub = ed25519PublicKey(ED_SK);
  expect(() => ed25519Verify(pub, new Uint8Array(0), new Uint8Array(63))).toThrow(SignError);
});
