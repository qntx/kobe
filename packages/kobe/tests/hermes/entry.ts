/**
 * Bundle entry for the Hermes smoke test: import the package entries and run BIP-39 / NIP-06 /
 * vault known-answer checks on Hermes.
 */
import { hexToBytes } from "@noble/hashes/utils.js";

import { Wallet } from "../../src/core/index.ts";
import { Secp256k1Signer } from "../../src/core/secp256k1.ts";
import { SecretKey } from "../../src/core/secret.ts";
import { EvmSigner } from "../../src/evm/index.ts";
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

// vectors/core/wallet-id.json case 0 (ABANDON, no passphrase).
const WALLET_ID = "4966e32ef7f4204b";

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

// vectors/core/secp256k1-ecdsa.json case 0 (signer/wallet RFC 6979 KAT).
const SECP_KEY = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
const SECP_DIGEST = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
const SECP_SIG =
  "68597f9553ac0acc453b5a75af2c731e3ca14dbfeae2231123fd202765b12738247bc920ef3e3ceebbc865651f98dc26a25a0d63240c5da091863fe0296e389b00";

// vectors/evm/sign.json personal-message case 0 (EIP-191 over "signer kat v3").
const EVM_EIP191_SIG =
  "bd238f0d6957ec577e5f90d781f63ff97e730ad39007e4bdde7b903af5f448762e2ef82e254d3c17337883c34a74d9fb0399226f818e4d1621377107f465f6901c";

function hex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

try {
  const wallet = Wallet.fromEntropy(new Uint8Array(16));
  if (wallet.mnemonic() !== ABANDON) {
    throw new Error("fromEntropy mnemonic mismatch");
  }
  if (wallet.id() !== WALLET_ID) {
    throw new Error("wallet id mismatch");
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

  const secpSecret = SecretKey.fromBytes(hexToBytes(SECP_KEY));
  const secpSigner = Secp256k1Signer.fromSecretKey(secpSecret);
  const secpOut = secpSigner.signRecoverable(hexToBytes(SECP_DIGEST));
  const secpRecoverable = new Uint8Array(65);
  secpRecoverable.set(secpOut.signature);
  secpRecoverable[64] = secpOut.recovery;
  if (hex(secpRecoverable) !== SECP_SIG) {
    throw new Error("secp256k1 recoverable signature mismatch");
  }
  if (!secpSigner.verify(hexToBytes(SECP_DIGEST), secpRecoverable)) {
    throw new Error("secp256k1 verify mismatch");
  }

  const evmSigner = EvmSigner.fromSecretKey(SecretKey.fromBytes(hexToBytes(SECP_KEY)));
  const eip191 = evmSigner.signPersonalMessage(new TextEncoder().encode("signer kat v3"));
  const eip191Wire = new Uint8Array(65);
  eip191Wire.set(eip191.signature);
  eip191Wire[64] = 27 + eip191.recovery;
  if (hex(eip191Wire) !== EVM_EIP191_SIG) {
    throw new Error("evm EIP-191 signature mismatch");
  }
  if (evmSigner.address() !== "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23") {
    throw new Error("evm address mismatch");
  }

  print("HERMES_SMOKE_OK");
} catch (error) {
  print(
    `HERMES_SMOKE_FAIL: ${error instanceof Error ? (error.stack ?? error.message) : String(error)}`,
  );
  quit(1);
}
