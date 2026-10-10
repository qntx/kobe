import { expect, test } from "vitest";
import {
  createNostrDeriver,
  createNostrSigner,
  nostrSignerFromHex,
  nostrSignerFromNsec,
} from "../../src/chains/nostr/index.ts";
import { bytesToHex } from "../../src/crypto/hex.ts";
import { sha256Bytes } from "../../src/crypto/index.ts";
import { walletFromMnemonic } from "../../src/hd/index.ts";
import { SignError, signOutputPublicKey, signOutputToBytes } from "../../src/sign/index.ts";

const TV1_PRIV = "7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a";
const TV1_PUB = "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917";
const TV1_NSEC = "nsec10allq0gjx7fddtzef0ax00mdps9t2kmtrldkyjfs8l5xruwvh2dq0lhhkp";
const TV1_NPUB = "npub1zutzeysacnf9rru6zqwmxd54mud0k44tst6l70ja5mhv8jjumytsd2x7nu";
const TV2_PRIV = "c15d739894c81a2fcfd3a2df85a0d2c0dbc47a280d092799f144d73d7ae78add";
const TV2_NPUB = "npub16sdj9zv4f8sl85e45vgq9n7nsgt5qphpvmf7vk8r5hhvmdjxx4es8rq74h";

test("gold: NIP-06 TV1 npub/nsec from key", () => {
  using s = nostrSignerFromHex(TV1_PRIV);
  expect(s.publicKeyHex()).toBe(TV1_PUB);
  expect(s.address()).toBe(TV1_NPUB);
  expect(s.nsec()).toBe(TV1_NSEC);
});

test("gold: NIP-06 TV2 npub", () => {
  using s = nostrSignerFromHex(TV2_PRIV);
  expect(s.address()).toBe(TV2_NPUB);
});

test("fromNsec round-trip and HRP reject", () => {
  using s = nostrSignerFromNsec(TV1_NSEC);
  expect(s.publicKeyHex()).toBe(TV1_PUB);
  expect(() => nostrSignerFromNsec(TV1_NPUB)).toThrow(SignError);
});

test("signTransaction equals signDigest(sha256(event))", () => {
  using s = nostrSignerFromHex(TV1_PRIV);
  const event = new TextEncoder().encode(`[0,"${TV1_PUB}",1700000000,1,[],"hi"]`);
  const a = s.signTransaction(event);
  const b = s.signDigest(sha256Bytes(event));
  expect(signOutputToBytes(a)).toEqual(signOutputToBytes(b));
  expect(s.verify(sha256Bytes(event), signOutputToBytes(a))).toBe(true);
  expect(bytesToHex(signOutputPublicKey(a)!)).toBe(TV1_PUB);
});

test("NIP-01 event sign/verify", () => {
  using s = nostrSignerFromHex(TV1_PRIV);
  const body = `[0,"${s.publicKeyHex()}",1700000000,1,[],"hello nostr"]`;
  const id = sha256Bytes(new TextEncoder().encode(body));
  const sig = s.signTransaction(new TextEncoder().encode(body));
  expect(signOutputToBytes(sig).length).toBe(64);
  expect(s.verify(id, signOutputToBytes(sig))).toBe(true);
});

test("createNostrSigner from derived account", () => {
  const w = walletFromMnemonic(
    "leader monkey parrot ring guide accident before fence cannon height naive bean",
  );
  using acct = createNostrDeriver(w).derive(0);
  w.dispose();
  using s = createNostrSigner(acct);
  expect(s.address()).toBe(acct.address);
});
