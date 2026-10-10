import { inspect } from "node:util";
import { expect, test } from "vitest";
import { createNostrDeriver } from "../../src/chains/nostr/index.ts";
import { walletFromMnemonic } from "../../src/hd/index.ts";

const TV1_MNEMONIC =
  "leader monkey parrot ring guide accident before fence cannon height naive bean";
const TV1_PRIV = "7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a";
const TV1_PUB = "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917";
const TV1_NSEC = "nsec10allq0gjx7fddtzef0ax00mdps9t2kmtrldkyjfs8l5xruwvh2dq0lhhkp";
const TV1_NPUB = "npub1zutzeysacnf9rru6zqwmxd54mud0k44tst6l70ja5mhv8jjumytsd2x7nu";

const TV2_MNEMONIC =
  "what bleak badge arrange retreat wolf trade produce cricket blur garlic valid proud rude strong choose busy staff weather area salt hollow arm fade";
const TV2_PRIV = "c15d739894c81a2fcfd3a2df85a0d2c0dbc47a280d092799f144d73d7ae78add";
const TV2_NPUB = "npub16sdj9zv4f8sl85e45vgq9n7nsgt5qphpvmf7vk8r5hhvmdjxx4es8rq74h";

test("gold: NIP-06 TV1", () => {
  const w = walletFromMnemonic(TV1_MNEMONIC);
  using a = createNostrDeriver(w).derive(0);
  expect(a.path).toBe("m/44'/1237'/0'/0/0");
  expect(a.privateKeyHex()).toBe(TV1_PRIV);
  expect(a.publicKeyHex()).toBe(TV1_PUB);
  expect(a.npub()).toBe(TV1_NPUB);
  expect(a.nsec()).toBe(TV1_NSEC);
  expect(a.address).toBe(TV1_NPUB);
  expect(a.publicKey.kind).toBe("secp256k1-xonly");
  w.dispose();
});

test("gold: NIP-06 TV2 24-word", () => {
  const w = walletFromMnemonic(TV2_MNEMONIC);
  using a = createNostrDeriver(w).derive(0);
  expect(a.privateKeyHex()).toBe(TV2_PRIV);
  expect(a.npub()).toBe(TV2_NPUB);
  w.dispose();
});

test("nsec redacted; throws after dispose", () => {
  const w = walletFromMnemonic(TV1_MNEMONIC);
  const a = createNostrDeriver(w).derive(0);
  expect(inspect(a)).toContain("[REDACTED]");
  expect(inspect(a)).not.toContain(TV1_NSEC);
  a.dispose();
  expect(() => a.nsec()).toThrow();
  w.dispose();
});
