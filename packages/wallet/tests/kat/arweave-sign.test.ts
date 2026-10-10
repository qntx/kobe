import { sha384 } from "@noble/hashes/sha2.js";
import { expect, test } from "vitest";
import {
  arweaveSignature65,
  arweaveSignerFromHex,
  arweaveTxIdFromOutput,
  createArweaveDeriver,
  createArweaveSigner,
  deepHash,
  deepHashBlob,
  deepHashList,
  deepHashListItems,
  SIGNATURE_LEN,
  signatureDataSegmentV2Ecdsa,
} from "../../src/chains/arweave/index.ts";
import { sha256Bytes } from "../../src/crypto/index.ts";
import { SignError, signOutputToBytes } from "../../src/sign/index.ts";
import { walletFromMnemonic } from "../../src/hd/index.ts";

const ABANDON_0_SK = "130721c87ce0ace0999c94a5943d055b224411eda752680ca24969d0837ff152";
const ABANDON_0_ADDR = "G3y00z9F3EvSzJprpIH6vPqHVZPH0rLqLrg0JOsd88Y";
const ABANDON_0_OWNER = "A9-agndOu82Va7G9inhR8lqV3LEbBkp0zK3PJ3zLbTtv";
const ABANDON_0_PK = "03df9a82774ebbcd956bb1bd8a7851f25a95dcb11b064a74ccadcf277ccb6d3b6f";
const SK1 = "0000000000000000000000000000000000000000000000000000000000000001";

test("gold: address/owner match kobe-arweave abandon 0", () => {
  using s = arweaveSignerFromHex(ABANDON_0_SK);
  expect(s.publicKeyHex()).toBe(ABANDON_0_PK);
  expect(s.address()).toBe(ABANDON_0_ADDR);
  expect(s.owner()).toBe(ABANDON_0_OWNER);
  expect(s.address()).not.toBe(s.owner());
  expect("signMessage" in s).toBe(false);
});

test("gold: deep_hash empty list is SHA-384(list0)", () => {
  expect(deepHashList([])).toEqual(sha384(new TextEncoder().encode("list0")));
});

test("deep_hash blob vs list and order", () => {
  const a = deepHash(deepHashBlob(new TextEncoder().encode("a")));
  const b = deepHash(deepHashListItems([deepHashBlob(new TextEncoder().encode("a"))]));
  expect(a).not.toEqual(b);
  const ab = deepHashList([
    deepHashBlob(new TextEncoder().encode("a")),
    deepHashBlob(new TextEncoder().encode("b")),
  ]);
  const ba = deepHashList([
    deepHashBlob(new TextEncoder().encode("b")),
    deepHashBlob(new TextEncoder().encode("a")),
  ]);
  expect(ab).not.toEqual(ba);
});

test("signDigest / signPayload recoverable shape and verify", () => {
  using s = arweaveSignerFromHex(SK1);
  const digest = new Uint8Array(32).fill(0x11);
  const out = s.signDigest(digest);
  expect(out.scheme).toBe("ecdsa_recoverable");
  const sig65 = arweaveSignature65(out);
  expect(sig65.length).toBe(SIGNATURE_LEN);
  expect(s.verifyDigest(digest, sig65)).toBe(true);

  const msg = new Uint8Array(48).fill(0xab);
  const payload = s.signPayload(msg);
  expect(s.verifyPayload(msg, arweaveSignature65(payload))).toBe(true);
  const viaDigest = s.signDigest(sha256Bytes(msg));
  expect(signOutputToBytes(payload).subarray(0, 64)).toEqual(
    signOutputToBytes(viaDigest).subarray(0, 64),
  );
});

test("transaction id is Base64URL(SHA-256(sig65))", () => {
  using s = arweaveSignerFromHex(SK1);
  const out = s.signDigest(new Uint8Array(32).fill(7));
  const id = arweaveTxIdFromOutput(out);
  expect(id.length).toBe(43);
});

test("signFormat2 rejects non-v2; v2 verifies", () => {
  using s = arweaveSignerFromHex(SK1);
  expect(() =>
    s.signFormat2({
      format: 1,
      target: new Uint8Array(),
      quantity: "0",
      reward: "0",
      lastTx: new Uint8Array(),
      tags: [],
      dataSize: 0,
      dataRoot: new Uint8Array(),
    }),
  ).toThrow(SignError);

  const fields = {
    format: 2,
    target: Uint8Array.of(0x01, 0x02),
    quantity: "1",
    reward: "1000",
    lastTx: new Uint8Array(),
    tags: [[new TextEncoder().encode("App-Name"), new TextEncoder().encode("kobe-test")]] as const,
    dataSize: 0,
    dataRoot: new Uint8Array(),
  };
  const out = s.signFormat2(fields);
  const preimage = signatureDataSegmentV2Ecdsa(fields);
  expect(preimage.length).toBe(48);
  expect(s.verifyPayload(preimage, arweaveSignature65(out))).toBe(true);
});

test("createArweaveSigner from derived account", () => {
  const w = walletFromMnemonic(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  );
  using acct = createArweaveDeriver(w).derive(0);
  w.dispose();
  using s = createArweaveSigner(acct);
  expect(s.address()).toBe(acct.address);
});
