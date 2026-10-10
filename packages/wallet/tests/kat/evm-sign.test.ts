import { expect, test } from "vitest";
import {
  concatEncoded,
  createEvmSigner,
  encodeBytes,
  encodeList,
  evmSignerFromHex,
  hashTypedDataJson,
  stripLeadingZeros,
} from "../../src/chains/evm/index.ts";
import { createDerivedAccount, walletFromMnemonic } from "../../src/hd/index.ts";
import { bytesToHex, hexToBytes } from "../../src/crypto/hex.ts";
import { signOutputToHex } from "../../src/sign/index.ts";

const PRIV = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
const ADDRESS = "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23";
const MESSAGE = "signer kat v3";
const SIGN_MESSAGE_EIP191_HEX =
  "bd238f0d6957ec577e5f90d781f63ff97e730ad39007e4bdde7b903af5f448762e2ef82e254d3c17337883c34a74d9fb0399226f818e4d1621377107f465f6901c";
const TX_HEX = "deadbeef00010203";
const SIGN_TRANSACTION_HEX =
  "c417ef54c6681102296b1af7f9692265f10cdf75a607f1ce66d57439889262e40d803bcafb4946ce29c22db851db7830f56d255095414a1f7e924c7f21df3a8101";

const EIP712_MAIL_JSON = `{
    "types": {
        "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
            {"name": "verifyingContract", "type": "address"}
        ],
        "Person": [
            {"name": "name", "type": "string"},
            {"name": "wallet", "type": "address"}
        ],
        "Mail": [
            {"name": "from", "type": "Person"},
            {"name": "to", "type": "Person"},
            {"name": "contents", "type": "string"}
        ]
    },
    "primaryType": "Mail",
    "domain": {
        "name": "Ether Mail",
        "version": "1",
        "chainId": 1,
        "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
    },
    "message": {
        "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
        "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
        "contents": "Hello, Bob!"
    }
}`;

test("gold: EIP-55 address from fixture key", () => {
  using s = evmSignerFromHex(PRIV);
  expect(s.address()).toBe(ADDRESS);
});

test("gold: EIP-191 personal_sign signer kat v3", () => {
  using s = evmSignerFromHex(PRIV);
  const out = s.signMessage(new TextEncoder().encode(MESSAGE));
  expect(signOutputToHex(out)).toBe(SIGN_MESSAGE_EIP191_HEX);
  expect(out.scheme).toBe("ecdsa_recoverable");
  if (out.scheme === "ecdsa_recoverable") {
    expect(out.v === 27 || out.v === 28).toBe(true);
  }
});

test("gold: EIP-712 Mail digest", () => {
  expect(bytesToHex(hashTypedDataJson(EIP712_MAIL_JSON))).toBe(
    "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2",
  );
});

test("gold: EIP-712 Mail sign v 27|28", () => {
  using s = evmSignerFromHex(PRIV);
  const out = s.signTypedData(EIP712_MAIL_JSON);
  expect(out.scheme).toBe("ecdsa_recoverable");
  if (out.scheme === "ecdsa_recoverable") {
    expect(out.v === 27 || out.v === 28).toBe(true);
  }
  expect(
    s.verifyHash(
      hashTypedDataJson(EIP712_MAIL_JSON),
      out.scheme === "ecdsa_recoverable" ? out.signature : new Uint8Array(),
    ),
  ).toBe(true);
});

test("shape: signTransaction raw v + keccak of unsigned bytes", () => {
  using s = evmSignerFromHex(PRIV);
  const tx = hexToBytes(TX_HEX);
  const out = s.signTransaction(tx);
  expect(signOutputToHex(out)).toBe(SIGN_TRANSACTION_HEX);
  if (out.scheme === "ecdsa_recoverable") {
    expect(out.v === 0 || out.v === 1).toBe(true);
  }
});

test("shape: encode EIP-1559 envelope keeps type 0x02", () => {
  using s = evmSignerFromHex(PRIV);
  const items = concatEncoded([
    encodeBytes(Uint8Array.of(1)),
    encodeBytes(new Uint8Array(0)),
    encodeBytes(new Uint8Array(0)),
    encodeBytes(new Uint8Array(0)),
    encodeBytes(new Uint8Array(0)),
    encodeBytes(new Uint8Array(0)),
    encodeBytes(new Uint8Array(0)),
    encodeBytes(new Uint8Array(0)),
    encodeList(new Uint8Array(0)),
  ]);
  const unsigned = new Uint8Array(1 + encodeList(items).length);
  unsigned[0] = 0x02;
  unsigned.set(encodeList(items), 1);
  const out = s.signTransaction(unsigned);
  const signed = s.encodeSignedTransaction(unsigned, out);
  expect(signed[0]).toBe(0x02);
});

test("stripLeadingZeros drops prefix zeros", () => {
  expect(stripLeadingZeros(Uint8Array.of(0, 0, 1))).toEqual(Uint8Array.of(1));
  expect(stripLeadingZeros(Uint8Array.of(0, 0, 0))).toEqual(new Uint8Array(0));
});

test("RLP integer 0 is 0x80 after strip", () => {
  expect(encodeBytes(stripLeadingZeros(new Uint8Array(0)))).toEqual(Uint8Array.of(0x80));
  expect(encodeBytes(stripLeadingZeros(Uint8Array.of(0, 0, 0)))).toEqual(Uint8Array.of(0x80));
});

test("RLP single byte < 0x80 stays bare after strip", () => {
  expect(encodeBytes(stripLeadingZeros(Uint8Array.of(0x00, 0x01)))).toEqual(Uint8Array.of(0x01));
});

test("createEvmSigner from derived account", () => {
  const w = walletFromMnemonic("test test test test test test test test test test test junk");
  const key = w.deriveSecp256k1("m/44'/60'/0'/0/0");
  const acct = createDerivedAccount({
    path: "m/44'/60'/0'/0/0",
    privateKey: key.privateKeyBytes(),
    publicKey: { kind: "secp256k1-uncompressed", bytes: key.uncompressedPublicKey() },
    address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
  });
  key.dispose();
  w.dispose();
  using s = createEvmSigner(acct);
  acct.dispose();
  expect(s.address()).toBe("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
});
