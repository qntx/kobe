/**
 * Bundle entry for the Hermes smoke test: import the package entries and run BIP-39 / NIP-06 /
 * vault known-answer checks on Hermes.
 */
import { hexToBytes } from "@noble/hashes/utils.js";

import { Wallet } from "../../src/core/index.ts";
import { NostrDeriver } from "../../src/nostr/index.ts";
import { derivePrfKey, open, passkeyWallet, seal } from "../../src/vault/index.ts";

declare function print(msg: string): void;
declare function quit(code: number): void;

// NIP-06 test vector 1, account 0.
const TV1_MNEMONIC =
  "leader monkey parrot ring guide accident before fence cannon height naive bean";
const TV1_NPUB = "npub1zutzeysacnf9rru6zqwmxd54mud0k44tst6l70ja5mhv8jjumytsd2x7nu";
const ABANDON =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// vectors/vault/seal.json case 0.
const SEAL_KEY = "0000000000000000000000000000000000000000000000000000000000000001";
const SEAL_NONCE = "0102030405060708090a0b0c";
const SEAL_CONTEXT = "kobe/test/v1/id-1/data";
const SEALED = "010102030405060708090a0b0c174fdcfdda669b37ac0db6ce6ad46a30";

// vectors/vault/prf-key.json case 0.
const PRF = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const PRF_INFO = "kobe/test/v1/kek";
const PRF_KEY = "e6cfcaf65be954c01e73902a2288a935d3e8f2c6d2c434e6c1d19c941e458917";

// vectors/vault/passkey-wallet.json case 0.
const PASSKEY_NPUB = "npub1y8d9v47f0w2muh9tswfhgej59r73gs26nndr4q8acxj7twwgydgserahqq";

function hex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

try {
  const wallet = Wallet.fromEntropy(new Uint8Array(16));
  if (wallet.mnemonic() !== ABANDON) {
    throw new Error("fromEntropy mnemonic mismatch");
  }
  const tv1 = Wallet.fromMnemonic(TV1_MNEMONIC);
  const account = new NostrDeriver(tv1).derive(0);
  if (account.npub() !== TV1_NPUB) {
    throw new Error("NIP-06 npub mismatch");
  }

  const sealed = seal(hexToBytes(SEAL_KEY), new Uint8Array(0), SEAL_CONTEXT, (out) =>
    out.set(hexToBytes(SEAL_NONCE)),
  );
  if (hex(sealed) !== SEALED) {
    throw new Error("vault seal mismatch");
  }
  if (open(hexToBytes(SEAL_KEY), sealed, SEAL_CONTEXT).length > 0) {
    throw new Error("vault open mismatch");
  }

  if (hex(derivePrfKey(hexToBytes(PRF), PRF_INFO)) !== PRF_KEY) {
    throw new Error("derivePrfKey mismatch");
  }

  const passkey = passkeyWallet(hexToBytes(PRF));
  if (new NostrDeriver(passkey).derive(0).npub() !== PASSKEY_NPUB) {
    throw new Error("passkeyWallet npub mismatch");
  }

  print("HERMES_SMOKE_OK");
} catch (error) {
  print(
    `HERMES_SMOKE_FAIL: ${error instanceof Error ? (error.stack ?? error.message) : String(error)}`,
  );
  quit(1);
}
