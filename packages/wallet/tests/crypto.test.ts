import { expect, test } from "vitest";
import {
  hash160,
  hash256,
  hmacSha512,
  keccak256,
  pbkdf2Sha256,
  pbkdf2Sha512,
  sha256Bytes,
} from "../src/crypto/index.ts";
import { bytesToHex } from "../src/crypto/hex.ts";

const empty = new Uint8Array(0);
const abc = new TextEncoder().encode("abc");

test("sha256 empty vector", () => {
  const h = sha256Bytes(empty);
  expect(Buffer.from(h).toString("hex")).toBe(
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  );
});

test("sha256 abc vector", () => {
  const h = sha256Bytes(abc);
  expect(Buffer.from(h).toString("hex")).toBe(
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  );
});

test("keccak256 empty (Ethereum)", () => {
  const h = keccak256(empty);
  expect(Buffer.from(h).toString("hex")).toBe(
    "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
  );
});

test("hmacSha512 produces 64 bytes", () => {
  const out = hmacSha512(new TextEncoder().encode("key"), abc);
  expect(out.length).toBe(64);
});

test("pbkdf2Sha512 bip39-shaped output length", () => {
  const out = pbkdf2Sha512(
    new TextEncoder().encode("password"),
    new TextEncoder().encode("salt"),
    1,
    64,
  );
  expect(out.length).toBe(64);
});

test("gold: PBKDF2-HMAC-SHA256 RFC 7914 §11 first block", () => {
  const out = pbkdf2Sha256(
    new TextEncoder().encode("passwd"),
    new TextEncoder().encode("salt"),
    1,
    32,
  );
  expect(bytesToHex(out)).toBe("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc");
});

test("hash256 and hash160 lengths", () => {
  expect(hash256(abc).length).toBe(32);
  expect(hash160(abc).length).toBe(20);
});
