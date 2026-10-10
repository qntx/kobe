import { readFileSync } from "node:fs";
import { join } from "node:path";

import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { base58 } from "@scure/base";
import { describe, expect, test } from "vite-plus/test";

import { deriveSecp256k1FromSeed } from "../../src/core/bip32.ts";
import { Ed25519Signer } from "../../src/core/ed25519.ts";
import { KobeError } from "../../src/core/error.ts";
import { expandMnemonic } from "../../src/core/expand.ts";
import { SchnorrSigner } from "../../src/core/schnorr.ts";
import { Secp256k1Signer } from "../../src/core/secp256k1.ts";
import { SecretKey } from "../../src/core/secret.ts";
import { deriveEd25519FromSeed } from "../../src/core/slip10.ts";
import { Wallet, walletSeed } from "../../src/core/wallet.ts";

const root = join(import.meta.dirname, "../../../../vectors");

const TREZOR = JSON.parse(readFileSync(join(root, "bip39/trezor.json"), "utf8")) as {
  english: Array<[entropy: string, mnemonic: string, seed: string, xprv: string]>;
};
const BIP39 = JSON.parse(readFileSync(join(root, "core/bip39.json"), "utf8")) as {
  cases: Array<{
    input?: string;
    mnemonic?: string;
    passphrase?: string;
    entropy?: string;
    seed?: string;
    wordCount?: number;
    error?: string;
  }>;
};
const BIP32 = JSON.parse(readFileSync(join(root, "core/bip32.json"), "utf8")) as {
  cases: Array<{
    mnemonic: string;
    passphrase?: string;
    path: string;
    privateKey?: string;
    compressedPublicKey?: string;
    uncompressedPublicKey?: string;
    error?: string;
  }>;
};
const BIP32_OFFICIAL = JSON.parse(readFileSync(join(root, "bip32/official.json"), "utf8")) as {
  cases: Array<{ seed: string; chains: Array<{ path: string; xpub: string; xprv: string }> }>;
};
const MNEMONIC_EXPAND = JSON.parse(
  readFileSync(join(root, "core/mnemonic-expand.json"), "utf8"),
) as { cases: Array<{ input: string; mnemonic?: string; error?: string }> };
const WALLET_ID = JSON.parse(readFileSync(join(root, "core/wallet-id.json"), "utf8")) as {
  cases: Array<{ mnemonic: string; passphrase?: string; masterPublicKey: string; id: string }>;
};
const SECRET_KEY = JSON.parse(readFileSync(join(root, "core/secret-key.json"), "utf8")) as {
  cases: Array<{ input: string; output?: string; error?: string }>;
};
const SECP256K1 = JSON.parse(readFileSync(join(root, "core/secp256k1-ecdsa.json"), "utf8")) as {
  cases: Array<{
    privateKey: string;
    digest?: string;
    compressedPublicKey?: string;
    uncompressedPublicKey?: string;
    signature?: string;
    recovery?: number;
    signatureDer?: string;
    valid?: boolean;
    error?: string;
  }>;
};
const BIP340 = JSON.parse(readFileSync(join(root, "core/bip340.json"), "utf8")) as {
  cases: Array<{
    index: number;
    secretKey?: string;
    publicKey: string;
    auxRand?: string;
    message: string;
    signature: string;
    valid: boolean;
  }>;
};
const ED25519 = JSON.parse(readFileSync(join(root, "core/ed25519.json"), "utf8")) as {
  cases: Array<{
    secretKey: string;
    publicKey: string;
    message: string;
    signature: string;
    valid: boolean;
  }>;
};
const SLIP10 = JSON.parse(readFileSync(join(root, "core/slip10.json"), "utf8")) as {
  cases: Array<{ seed: string; path: string; privateKey: string; publicKey: string }>;
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

// Case partitions are computed outside the test callbacks: `??`, `||` and
// ternaries inside `test` are rejected by the no-conditional-in-test lint.
const bip39Valid = BIP39.cases.filter((c) => c.error === undefined && c.entropy !== undefined);
const bip39Normalize = bip39Valid
  .filter((c) => c.input !== undefined)
  .map((c) => ({ input: c.input ?? "", mnemonic: c.mnemonic ?? "" }));
const bip39EntropyCases = bip39Valid
  .filter((c) => c.input === undefined)
  .map((c) => ({
    entropy: c.entropy ?? "",
    mnemonic: c.mnemonic ?? "",
    passphrase: c.passphrase ?? "",
    seed: c.seed ?? "",
    wordCount: c.wordCount ?? 0,
  }));
const bip39PhraseErrors = BIP39.cases
  .filter((c) => c.input !== undefined && c.error !== undefined)
  .map((c) => ({ input: c.input ?? "", error: c.error ?? "" }));
const bip39EntropyErrors = BIP39.cases
  .filter((c) => c.input === undefined && c.error !== undefined)
  .map((c) => ({ entropy: c.entropy ?? "", error: c.error ?? "" }));

const bip32Cases = BIP32.cases.map((c) => ({ ...c, passphrase: c.passphrase ?? "" }));
const bip32Valid = bip32Cases.filter((c) => c.error === undefined);
const bip32Invalid = bip32Cases.filter((c) => c.error !== undefined);

const expandValid = MNEMONIC_EXPAND.cases.filter((c) => c.error === undefined);
const expandInvalid = MNEMONIC_EXPAND.cases.filter((c) => c.error !== undefined);

const walletIdCases = WALLET_ID.cases.map((c) => ({ ...c, passphrase: c.passphrase ?? "" }));

const secretKeyValid = SECRET_KEY.cases.filter((c) => c.error === undefined);
const secretKeyInvalid = SECRET_KEY.cases.filter((c) => c.error !== undefined);

// Normalized outside the test callbacks: `??` and `if` inside `test` are
// rejected by the no-conditional-in-test lint.
const secp256k1Normalized = SECP256K1.cases.map((c) => ({
  privateKey: c.privateKey,
  digest: c.digest ?? "",
  compressedPublicKey: c.compressedPublicKey ?? "",
  uncompressedPublicKey: c.uncompressedPublicKey ?? "",
  signature: c.signature ?? "",
  recovery: c.recovery ?? 0,
  signatureDer: c.signatureDer ?? "",
  valid: c.valid ?? true,
  error: c.error,
}));
const secp256k1Sign = secp256k1Normalized.filter((c) => c.error === undefined && c.valid);
const secp256k1VerifyFalse = secp256k1Normalized.filter((c) => c.error === undefined && !c.valid);
const secp256k1KeyErrors = secp256k1Normalized.filter(
  (c) => c.error !== undefined && c.digest === "",
);
const secp256k1DigestErrors = secp256k1Normalized.filter(
  (c) => c.error !== undefined && c.digest !== "",
);

const bip340Sign = BIP340.cases
  .filter((c) => c.secretKey !== undefined)
  .map((c) => ({ ...c, secretKey: c.secretKey ?? "", auxRand: c.auxRand ?? "" }));

const ed25519Sign = ED25519.cases.filter((c) => c.valid);
const ed25519VerifyFalse = ED25519.cases.filter((c) => !c.valid);

describe("vectors/bip39/trezor.json", () => {
  test("entropy → mnemonic and mnemonic → seed (passphrase TREZOR)", () => {
    expect(TREZOR.english.length).toBeGreaterThan(0);
    for (const [entropy, mnemonic, seed] of TREZOR.english) {
      const wallet = Wallet.fromEntropy(hexToBytes(entropy), "TREZOR");
      expect(wallet.mnemonic()).toBe(mnemonic);
      expect(bytesToHex(walletSeed(wallet))).toBe(seed);
      wallet.dispose();

      const rebuilt = Wallet.fromMnemonic(mnemonic, "TREZOR");
      expect(bytesToHex(walletSeed(rebuilt))).toBe(seed);
      rebuilt.dispose();
    }
  });
});

describe("vectors/core/bip39.json", () => {
  test("entropy → mnemonic, seed and word count", () => {
    for (const c of bip39EntropyCases) {
      const wallet = Wallet.fromEntropy(hexToBytes(c.entropy), c.passphrase);
      expect(wallet.mnemonic()).toBe(c.mnemonic);
      expect(wallet.wordCount).toBe(c.wordCount);
      expect(bytesToHex(walletSeed(wallet))).toBe(c.seed);
      wallet.dispose();

      const rebuilt = Wallet.fromMnemonic(c.mnemonic, c.passphrase);
      expect(bytesToHex(walletSeed(rebuilt))).toBe(c.seed);
      rebuilt.dispose();
    }
  });

  test("whitespace normalization", () => {
    for (const c of bip39Normalize) {
      const wallet = Wallet.fromMnemonic(c.input);
      expect(wallet.mnemonic()).toBe(c.mnemonic);
      wallet.dispose();
    }
  });

  test("invalid phrases share the error codes", () => {
    for (const c of bip39PhraseErrors) {
      expect(codeOf(() => Wallet.fromMnemonic(c.input))).toBe(c.error);
    }
  });

  test("invalid entropy lengths share the error codes", () => {
    for (const c of bip39EntropyErrors) {
      expect(codeOf(() => Wallet.fromEntropy(hexToBytes(c.entropy)))).toBe(c.error);
    }
  });
});

describe("vectors/core/bip32.json", () => {
  test("derive secp256k1 keys", () => {
    for (const c of bip32Valid) {
      const wallet = Wallet.fromMnemonic(c.mnemonic, c.passphrase);
      const key = wallet.deriveSecp256k1(c.path);
      expect(key.privateKeyHex()).toBe(c.privateKey);
      expect(key.compressedPublicKeyHex()).toBe(c.compressedPublicKey);
      expect(key.uncompressedPublicKeyHex()).toBe(c.uncompressedPublicKey);
      key.dispose();
      wallet.dispose();
    }
  });

  test("malformed paths share the error codes", () => {
    for (const c of bip32Invalid) {
      const wallet = Wallet.fromMnemonic(c.mnemonic, c.passphrase);
      expect(codeOf(() => wallet.deriveSecp256k1(c.path))).toBe(c.error);
      wallet.dispose();
    }
  });
});

describe("vectors/bip32/official.json", () => {
  test("official vectors 1-4 derive xprv/xpub payloads from raw seeds", () => {
    for (const c of BIP32_OFFICIAL.cases) {
      const seed = hexToBytes(c.seed);
      for (const chain of c.chains) {
        const key = deriveSecp256k1FromSeed(seed, chain.path);
        // Base58Check payload only — the checksum is not under test.
        const xprv = base58.decode(chain.xprv);
        const xpub = base58.decode(chain.xpub);
        expect(bytesToHex(key.privateKeyBytes())).toBe(bytesToHex(xprv.slice(46, 78)));
        expect(bytesToHex(key.compressedPublicKey())).toBe(bytesToHex(xpub.slice(45, 78)));
        key.dispose();
      }
    }
  });
});

describe("vectors/core/wallet-id.json", () => {
  test("id = hex(sha256('kobe/wallet-id/v1' ‖ compressed BIP-32 master pubkey))[..16]", () => {
    for (const c of walletIdCases) {
      const wallet = Wallet.fromMnemonic(c.mnemonic, c.passphrase);
      // The master pubkey is pinned separately so a BIP-32 divergence
      // between @scure/bip32 and the Rust `bip32` crate cannot hide in the hash.
      const master = wallet.deriveSecp256k1("m");
      expect(master.compressedPublicKeyHex()).toBe(c.masterPublicKey);
      master.dispose();
      expect(wallet.id()).toBe(c.id);
      wallet.dispose();
    }
  });
});

describe("vectors/core/mnemonic-expand.json", () => {
  test("expand prefixes to full words", () => {
    for (const c of expandValid) {
      expect(expandMnemonic(c.input)).toBe(c.mnemonic);
    }
  });

  test("invalid prefixes share the error codes", () => {
    for (const c of expandInvalid) {
      expect(codeOf(() => expandMnemonic(c.input))).toBe(c.error);
    }
  });
});

describe("vectors/core/secret-key.json", () => {
  test("32-byte secret round-trips through SecretKey", () => {
    for (const c of secretKeyValid) {
      const key = SecretKey.fromBytes(hexToBytes(c.input));
      expect(bytesToHex(key.toBytes())).toBe(c.output);
      key.dispose();
    }
  });

  test("wrong lengths share the error codes", () => {
    for (const c of secretKeyInvalid) {
      expect(codeOf(() => SecretKey.fromBytes(hexToBytes(c.input)))).toBe(c.error);
    }
  });
});

describe("vectors/core/secp256k1-ecdsa.json", () => {
  test("sign + public keys + verify (KAT and bitcoinjs fixtures)", () => {
    for (const c of secp256k1Sign) {
      const secret = SecretKey.fromBytes(hexToBytes(c.privateKey));
      const signer = Secp256k1Signer.fromSecretKey(secret);
      const digest = hexToBytes(c.digest);
      expect(bytesToHex(signer.compressedPublicKey())).toBe(c.compressedPublicKey);
      expect(bytesToHex(signer.uncompressedPublicKey())).toBe(c.uncompressedPublicKey);
      const out = signer.signRecoverable(digest);
      expect(bytesToHex(out.signature)).toBe(c.signature);
      expect(out.recovery).toBe(c.recovery);
      expect(bytesToHex(signer.signDer(digest))).toBe(c.signatureDer);
      const recoverable = new Uint8Array(65);
      recoverable.set(out.signature);
      recoverable[64] = out.recovery;
      expect(signer.verify(digest, recoverable)).toBe(true);
      signer.dispose();
      secret.dispose();
    }
  });

  test("tampered signatures verify false", () => {
    for (const c of secp256k1VerifyFalse) {
      const secret = SecretKey.fromBytes(hexToBytes(c.privateKey));
      const signer = Secp256k1Signer.fromSecretKey(secret);
      const recoverable = new Uint8Array(65);
      recoverable.set(hexToBytes(c.signature));
      recoverable[64] = c.recovery;
      expect(signer.verify(hexToBytes(c.digest), recoverable)).toBe(false);
      signer.dispose();
      secret.dispose();
    }
  });

  test("invalid keys share the error codes", () => {
    for (const c of secp256k1KeyErrors) {
      expect(
        codeOf(() => Secp256k1Signer.fromSecretKey(SecretKey.fromBytes(hexToBytes(c.privateKey)))),
      ).toBe(c.error);
    }
  });

  test("wrong-length digests share the error codes", () => {
    for (const c of secp256k1DigestErrors) {
      const secret = SecretKey.fromBytes(hexToBytes(c.privateKey));
      const signer = Secp256k1Signer.fromSecretKey(secret);
      expect(codeOf(() => signer.signRecoverable(hexToBytes(c.digest)))).toBe(c.error);
      signer.dispose();
      secret.dispose();
    }
  });
});

describe("vectors/core/bip340.json", () => {
  test("rows with a secret key sign deterministically", () => {
    for (const c of bip340Sign) {
      const secret = SecretKey.fromBytes(hexToBytes(c.secretKey));
      const signer = SchnorrSigner.fromSecretKey(secret);
      expect(bytesToHex(signer.xonlyPublicKey())).toBe(c.publicKey);
      const sig = signer.sign(hexToBytes(c.message), hexToBytes(c.auxRand));
      expect(bytesToHex(sig)).toBe(c.signature);
      signer.dispose();
      secret.dispose();
    }
  });

  test("all rows verify to the expected boolean (invalid pubkeys → false)", () => {
    for (const c of BIP340.cases) {
      const ok = SchnorrSigner.verifyWith(
        hexToBytes(c.publicKey),
        hexToBytes(c.message),
        hexToBytes(c.signature),
      );
      expect(ok).toBe(c.valid);
    }
  });
});

describe("vectors/core/ed25519.json", () => {
  test("RFC 8032 cases sign and verify", () => {
    for (const c of ed25519Sign) {
      const secret = SecretKey.fromBytes(hexToBytes(c.secretKey));
      const signer = Ed25519Signer.fromSecretKey(secret);
      const message = hexToBytes(c.message);
      expect(bytesToHex(signer.publicKey())).toBe(c.publicKey);
      expect(bytesToHex(signer.sign(message))).toBe(c.signature);
      expect(signer.verify(message, hexToBytes(c.signature))).toBe(true);
      signer.dispose();
      secret.dispose();
    }
  });

  test("tampered signatures verify false", () => {
    for (const c of ed25519VerifyFalse) {
      const secret = SecretKey.fromBytes(hexToBytes(c.secretKey));
      const signer = Ed25519Signer.fromSecretKey(secret);
      expect(signer.verify(hexToBytes(c.message), hexToBytes(c.signature))).toBe(false);
      signer.dispose();
      secret.dispose();
    }
  });
});

describe("vectors/core/slip10.json", () => {
  test("SLIP-10 Ed25519 derivation matches official chains", () => {
    for (const c of SLIP10.cases) {
      const key = deriveEd25519FromSeed(hexToBytes(c.seed), c.path);
      expect(key.privateKeyHex()).toBe(c.privateKey);
      expect(key.publicKeyHex()).toBe(c.publicKey);
      key.dispose();
    }
  });
});
