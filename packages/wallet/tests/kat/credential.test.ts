import { gcm } from "@noble/ciphers/aes.js";
import { expect, test } from "vitest";
import { pbkdf2Sha256 } from "../../src/crypto/index.ts";
import { DeriveError } from "../../src/errors/derive.ts";
import { walletFromMnemonic } from "../../src/hd/index.ts";
import {
  credentialFromBytes,
  credentialToBytes,
  decryptBytes,
  decryptMnemonic,
  decryptSecret32,
  encryptBytes,
  encryptMnemonic,
  encryptSecret32,
} from "../../src/secret/index.ts";
import { createEvmDeriver } from "../../src/chains/evm/index.ts";

const PHRASE =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const PASS = "kernel-pass-2026";
const ITER = 1000;

function rng(seq: number): (bytes: Uint8Array) => void {
  return (bytes) => {
    for (let i = 0; i < bytes.length; i++) bytes[i] = (seq + i) & 0xff;
  };
}

test("encrypt/decrypt bytes and envelope round-trip", () => {
  const pt = new TextEncoder().encode("kernel");
  const blob = encryptBytes(pt, PASS, { iterations: ITER, rng: rng(7) });
  expect(blob.version).toBe(2);
  expect(blob.salt.length).toBe(32);
  expect(blob.nonce.length).toBe(12);
  expect(decryptBytes(blob, PASS)).toEqual(pt);
  const wire = credentialToBytes(blob);
  expect(wire[4]).toBe(2);
  expect(wire[10]).toBe(32);
  expect(wire[43]).toBe(12);
  expect(wire.subarray(6, 10)).toEqual(new Uint8Array([0x00, 0x00, 0x03, 0xe8]));
  expect(new DataView(wire.buffer, wire.byteOffset, wire.byteLength).getUint32(6, false)).toBe(
    ITER,
  );
  expect(decryptBytes(credentialFromBytes(wire), PASS)).toEqual(pt);
});

test("wrong password and empty password fail closed", () => {
  const blob = encryptBytes(new Uint8Array([1, 2, 3]), PASS, { iterations: ITER, rng: rng(1) });
  expect(() => decryptBytes(blob, "nope")).toThrow(DeriveError);
  expect(() => encryptBytes(new Uint8Array([1]), "")).toThrow(DeriveError);
});

test("tamper ciphertext fails closed", () => {
  const blob = encryptBytes(new Uint8Array([9]), PASS, { iterations: ITER, rng: rng(2) });
  const ct = new Uint8Array(blob.ciphertext);
  ct[0] = (ct[0] ?? 0) ^ 0xff;
  expect(() => decryptBytes({ ...blob, ciphertext: ct }, PASS)).toThrow(DeriveError);
});

test("header bit-flip fails closed", () => {
  const blob = encryptBytes(new Uint8Array([9]), PASS, { iterations: ITER, rng: rng(5) });
  const wire = credentialToBytes(blob);
  const saltFlip = new Uint8Array(wire);
  saltFlip[11] = (saltFlip[11] ?? 0) ^ 0xff;
  expect(() => decryptBytes(credentialFromBytes(saltFlip), PASS)).toThrow(DeriveError);
  const verFlip = new Uint8Array(wire);
  verFlip[4] = 1;
  expect(() => credentialFromBytes(verFlip)).toThrow(/unsupported credential version 1/);
});

test("gcm aad is envelope header through nonce", () => {
  const pt = new Uint8Array([9]);
  const blob = encryptBytes(pt, PASS, { iterations: ITER, rng: rng(5) });
  const wire = credentialToBytes(blob);
  const header = wire.subarray(0, wire.length - blob.ciphertext.length);
  expect(header.length).toBe(56);
  expect(wire.subarray(header.length)).toEqual(blob.ciphertext);
  const key = pbkdf2Sha256(new TextEncoder().encode(PASS), blob.salt, ITER, 32);
  expect(() => gcm(key, blob.nonce).decrypt(blob.ciphertext)).toThrow();
  expect(gcm(key, blob.nonce, header).decrypt(blob.ciphertext)).toEqual(pt);
});

test("v1 envelope fails closed", () => {
  const saltLen = 16;
  const nonceLen = 12;
  const v1 = new Uint8Array(4 + 1 + 1 + 4 + 1 + saltLen + 1 + nonceLen + 16);
  v1.set(new TextEncoder().encode("WSEC"));
  v1[4] = 1;
  v1[5] = 1;
  new DataView(v1.buffer).setUint32(6, 600_000, false);
  v1[10] = saltLen;
  v1[11 + saltLen] = nonceLen;
  expect(() => credentialFromBytes(v1)).toThrow(DeriveError);
  expect(() => credentialFromBytes(v1)).toThrow(/unsupported credential version 1/);
});

test("saltLen other than 32 fails closed", () => {
  const blob = encryptBytes(new Uint8Array([1]), PASS, { iterations: ITER, rng: rng(6) });
  const wire = credentialToBytes(blob);
  wire[10] = 16;
  expect(() => credentialFromBytes(wire)).toThrow(/credential salt length/);
});

test("mnemonic blob restores the same EVM address", () => {
  const blob = encryptMnemonic(PHRASE, PASS, { iterations: ITER, rng: rng(3) });
  const phrase = decryptMnemonic(blob, PASS);
  const a = walletFromMnemonic(PHRASE);
  const b = walletFromMnemonic(phrase);
  expect(createEvmDeriver(a).derive(0).address).toBe(createEvmDeriver(b).derive(0).address);
  a.dispose();
  b.dispose();
});

test("secret32 length enforced", () => {
  const sk = new Uint8Array(32).fill(4);
  const blob = encryptSecret32(sk, PASS, { iterations: ITER, rng: rng(4) });
  expect(decryptSecret32(blob, PASS)).toEqual(sk);
  expect(() => encryptSecret32(new Uint8Array(31), PASS, { iterations: ITER })).toThrow(
    DeriveError,
  );
});
