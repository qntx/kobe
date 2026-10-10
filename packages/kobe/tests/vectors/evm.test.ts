import { readFileSync } from "node:fs";
import { join } from "node:path";

import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, test } from "vite-plus/test";

import { KobeError } from "../../src/core/error.ts";
import { SecretKey } from "../../src/core/secret.ts";
import { Wallet } from "../../src/core/wallet.ts";
import {
  authorizationHash,
  EvmDeriver,
  encodeSignature,
  encodeSignedTransaction,
  EvmSigner,
  evmPath,
  parseAddress,
  personalMessageHash,
  recoverAddress,
  toChecksum,
  transactionHash,
  typedDataHash,
} from "../../src/evm/index.ts";
import type { EvmDerivationStyle } from "../../src/evm/index.ts";

const root = join(import.meta.dirname, "../../../../vectors");

const DERIVE = JSON.parse(readFileSync(join(root, "evm/derive.json"), "utf8")) as {
  cases: Array<{
    mnemonic: string;
    passphrase?: string;
    style: EvmDerivationStyle;
    index: number;
    path: string;
    publicKey: string;
    address: string;
  }>;
};
const SIGN = JSON.parse(readFileSync(join(root, "evm/sign.json"), "utf8")) as {
  secretKey: string;
  cases: Array<{
    kind: "personal-message" | "authorization";
    message?: string;
    chainId?: string;
    address?: string;
    nonce?: string;
    hash: string;
    signature: string;
    recovery: number;
    encoded: string;
  }>;
};
const ENCODE = JSON.parse(readFileSync(join(root, "evm/encode.json"), "utf8")) as {
  cases: Array<{
    name: string;
    type?: string;
    unsigned: string;
    hash?: string;
    signature?: string;
    recovery?: number;
    signed?: string;
    error?: string;
  }>;
};
const EIP712 = JSON.parse(readFileSync(join(root, "evm/eip712.json"), "utf8")) as {
  cases: Array<{
    name: string;
    typedData: string;
    hash?: string;
    secretKey?: string;
    signature?: string;
    recovery?: number;
    error?: string;
  }>;
};
const ADDRESS = JSON.parse(readFileSync(join(root, "evm/address.json"), "utf8")) as {
  cases: Array<{
    kind: "parse" | "recover";
    address: string;
    error?: string;
    digest?: string;
    signature?: string;
    recovery?: number;
  }>;
};

/** Run `f`, returning the thrown `KobeError.code`; sentinels keep assertions unconditional. */
function codeOf(f: () => unknown): string {
  try {
    f();
  } catch (error) {
    return error instanceof KobeError ? error.code : "<non-KobeError thrown>";
  }
  return "<no error thrown>";
}

const deriveCases = DERIVE.cases.map((c) => ({ ...c, passphrase: c.passphrase ?? "" }));

const SIGN_SECRET = SecretKey.fromBytes(hexToBytes(SIGN.secretKey));
const personalCases = SIGN.cases
  .filter((c) => c.kind === "personal-message")
  .map((c) => ({
    message: c.message ?? "",
    hash: c.hash,
    signature: c.signature,
    recovery: c.recovery,
    encoded: c.encoded,
  }));
const authorizationCases = SIGN.cases
  .filter((c) => c.kind === "authorization")
  .map((c) => ({
    chainId: c.chainId ?? "0",
    address: c.address ?? "",
    nonce: c.nonce ?? "0",
    hash: c.hash,
    signature: c.signature,
    recovery: c.recovery,
  }));

const encodeValid = ENCODE.cases
  .filter((c) => c.error === undefined)
  .map((c) => ({
    unsigned: c.unsigned,
    hash: c.hash ?? "",
    signature: c.signature ?? "",
    recovery: c.recovery ?? 0,
    signed: c.signed ?? "",
  }));
const encodeErrors = ENCODE.cases
  .filter((c) => c.error !== undefined)
  .map((c) => ({ unsigned: c.unsigned, error: c.error ?? "" }));

const eip712Valid = EIP712.cases
  .filter((c) => c.error === undefined)
  .map((c) => ({
    typedData: c.typedData,
    hash: c.hash ?? "",
    secretKey: c.secretKey ?? SIGN.secretKey,
    signature: c.signature ?? "",
    recovery: c.recovery ?? 0,
  }));
const eip712Errors = EIP712.cases
  .filter((c) => c.error !== undefined)
  .map((c) => ({ typedData: c.typedData, error: c.error ?? "" }));

const parseValid = ADDRESS.cases
  .filter((c) => c.kind === "parse" && c.error === undefined)
  .map((c) => ({
    address: c.address,
    checksummed: /[a-f]/.test(c.address) && /[A-F]/.test(c.address),
  }));
const parseValidChecksummed = parseValid.filter((c) => c.checksummed);
const parseInvalid = ADDRESS.cases
  .filter((c) => c.kind === "parse" && c.error !== undefined)
  .map((c) => ({ address: c.address, error: c.error ?? "" }));
const recoverCases = ADDRESS.cases
  .filter((c) => c.kind === "recover")
  .map((c) => ({
    digest: c.digest ?? "",
    signature: c.signature ?? "",
    recovery: (c.recovery ?? 0) as 0 | 1,
    address: c.address,
  }));

describe("evm.derive", () => {
  test("derive EVM accounts for every style and index", () => {
    for (const c of deriveCases) {
      const wallet = Wallet.fromMnemonic(c.mnemonic, c.passphrase);
      try {
        const account = new EvmDeriver(wallet).deriveWith(c.style, c.index);
        try {
          expect(account.path).toBe(c.path);
          expect(evmPath(c.style, c.index)).toBe(c.path);
          expect(account.address).toBe(c.address);
          expect(account.publicKey.kind).toBe("secp256k1-uncompressed");
          expect(bytesToHex(account.publicKey.bytes)).toBe(c.publicKey);
        } finally {
          account.dispose();
        }
      } finally {
        wallet.dispose();
      }
    }
  });
});

describe("evm.sign", () => {
  test("personal messages hash and sign to the vector bytes", () => {
    for (const c of personalCases) {
      const signer = EvmSigner.fromSecretKey(SIGN_SECRET);
      try {
        const message = hexToBytes(c.message);
        expect(bytesToHex(personalMessageHash(message))).toBe(c.hash);
        const sig = signer.signPersonalMessage(message);
        expect(bytesToHex(sig.signature)).toBe(c.signature);
        expect(sig.recovery).toBe(c.recovery);
        expect(bytesToHex(encodeSignature(sig))).toBe(c.encoded);
        expect(recoverAddress(hexToBytes(c.hash), sig)).toBe(signer.address());
      } finally {
        signer.dispose();
      }
    }
  });

  test("authorizations hash and sign to the vector bytes", () => {
    for (const c of authorizationCases) {
      const signer = EvmSigner.fromSecretKey(SIGN_SECRET);
      try {
        const chainId = BigInt(c.chainId);
        const nonce = BigInt(c.nonce);
        expect(bytesToHex(authorizationHash(chainId, c.address, nonce))).toBe(c.hash);
        const sig = signer.signAuthorization(chainId, c.address, nonce);
        expect(bytesToHex(sig.signature)).toBe(c.signature);
        expect(sig.recovery).toBe(c.recovery);
        expect(recoverAddress(hexToBytes(c.hash), sig)).toBe(signer.address());
      } finally {
        signer.dispose();
      }
    }
  });
});

describe("evm.encode", () => {
  test("unsigned envelopes hash, sign and encode to the vector bytes", () => {
    for (const c of encodeValid) {
      const unsigned = hexToBytes(c.unsigned);
      const signer = EvmSigner.fromSecretKey(SIGN_SECRET);
      try {
        const hash = transactionHash(unsigned);
        expect(bytesToHex(hash)).toBe(c.hash);
        const sig = signer.signTransaction(unsigned);
        expect(bytesToHex(sig.signature)).toBe(c.signature);
        expect(sig.recovery).toBe(c.recovery);
        expect(recoverAddress(hash, sig)).toBe(signer.address());
        expect(bytesToHex(encodeSignedTransaction(unsigned, sig))).toBe(c.signed);
      } finally {
        signer.dispose();
      }
    }
  });

  test("malformed envelopes share the error codes", () => {
    for (const c of encodeErrors) {
      const unsigned = hexToBytes(c.unsigned);
      expect(codeOf(() => transactionHash(unsigned))).toBe(c.error);
      expect(
        codeOf(() =>
          encodeSignedTransaction(unsigned, { signature: new Uint8Array(64), recovery: 0 }),
        ),
      ).toBe(c.error);
    }
  });
});

describe("evm.eip712", () => {
  test("typed data hashes and signs to the vector bytes", () => {
    for (const c of eip712Valid) {
      const hash = typedDataHash(c.typedData);
      expect(bytesToHex(hash)).toBe(c.hash);
      const signer = EvmSigner.fromSecretKey(SecretKey.fromBytes(hexToBytes(c.secretKey)));
      try {
        const sig = signer.signTypedData(c.typedData);
        expect(bytesToHex(sig.signature)).toBe(c.signature);
        expect(sig.recovery).toBe(c.recovery);
        expect(recoverAddress(hash, sig)).toBe(signer.address());
      } finally {
        signer.dispose();
      }
    }
  });

  test("malformed typed data shares the error codes", () => {
    for (const c of eip712Errors) {
      expect(codeOf(() => typedDataHash(c.typedData))).toBe(c.error);
    }
  });
});

describe("evm.address", () => {
  test("valid addresses parse to their bytes", () => {
    for (const c of parseValid) {
      const bytes = parseAddress(c.address);
      expect(bytesToHex(bytes)).toBe(c.address.slice(2).toLowerCase());
    }
  });

  test("checksummed addresses round-trip through toChecksum", () => {
    for (const c of parseValidChecksummed) {
      expect(toChecksum(parseAddress(c.address))).toBe(c.address);
    }
  });

  test("invalid addresses share the error codes", () => {
    for (const c of parseInvalid) {
      expect(codeOf(() => parseAddress(c.address))).toBe(c.error);
    }
  });

  test("signatures recover to the signing address", () => {
    for (const c of recoverCases) {
      const sig = { signature: hexToBytes(c.signature), recovery: c.recovery };
      expect(recoverAddress(hexToBytes(c.digest), sig)).toBe(c.address);
    }
  });
});
