import { expect, test } from "vitest";
import {
  casperSignerFromHex,
  createCasperDeriver,
  createCasperSigner,
} from "../../src/chains/casper/index.ts";
import { SignError, signOutputToBytes } from "../../src/sign/index.ts";
import { walletFromMnemonic } from "../../src/hd/index.ts";

const SECP_HEX = "9c72144893c3ca5fa7299e65a7d7d6c41ab6a7add5f9860618324854d3c369d1";
const ED_HEX = "619386127005778f66a68fa91518c0841f59495790bb796fc781ecdd54fe329a";

test("default algo is secp; signDigest is recoverable ECDSA", () => {
  using s = casperSignerFromHex(SECP_HEX);
  expect(s.algo()).toBe("secp256k1");
  expect(s.taggedPublicKeyHex().startsWith("02")).toBe(true);
  expect(s.publicKeyBytes().length).toBe(33);
  const out = s.signDigest(new Uint8Array(32).fill(0x42));
  expect(out.scheme).toBe("ecdsa_recoverable");
  if (out.scheme === "ecdsa_recoverable") {
    expect(out.v === 0 || out.v === 1).toBe(true);
  }
  expect("address" in s).toBe(false);
  expect("signMessage" in s).toBe(false);
  expect("signTransaction" in s).toBe(false);
});

test("ed25519 signBytes is RFC 8032", () => {
  using s = casperSignerFromHex(ED_HEX, "ed25519");
  expect(s.algo()).toBe("ed25519");
  expect(s.taggedPublicKeyHex().startsWith("01")).toBe(true);
  const out = s.signBytes(new TextEncoder().encode("casper-test"));
  expect(out.scheme).toBe("ed25519");
  expect(signOutputToBytes(out).length).toBe(64);
});

test("secp signBytes rejects non-32-byte input", () => {
  using s = casperSignerFromHex(SECP_HEX);
  expect(() => s.signBytes(new TextEncoder().encode("nope"))).toThrow(SignError);
});

test("createCasperSigner infers algo from derived account", () => {
  const w = walletFromMnemonic(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  );
  using secpAcct = createCasperDeriver(w).derive(0);
  using edAcct = createCasperDeriver(w, "ed25519").derive(0);
  w.dispose();
  using secp = createCasperSigner(secpAcct);
  using ed = createCasperSigner(edAcct);
  expect(secp.algo()).toBe("secp256k1");
  expect(ed.algo()).toBe("ed25519");
  expect(secp.taggedPublicKeyHex()).toBe(secpAcct.taggedPublicKeyHex());
  expect(ed.taggedPublicKeyHex()).toBe(edAcct.taggedPublicKeyHex());
});
