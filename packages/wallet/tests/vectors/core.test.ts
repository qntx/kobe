import { readFileSync } from "node:fs";
import { join } from "node:path";

import { base58 } from "@scure/base";
import { describe, expect, test } from "vite-plus/test";

import { deriveSecp256k1FromSeed } from "../../src/bip32/index.ts";
import { bytesToHex, hexToBytes } from "../../src/crypto/hex.ts";
import { DeriveError } from "../../src/errors/derive.ts";
import { SignError } from "../../src/errors/sign.ts";
import { VaultError } from "../../src/errors/vault.ts";
import { expandMnemonic, walletFromEntropy, walletFromMnemonic } from "../../src/hd/index.ts";
import { walletSeedBytes } from "../../src/hd/raw-seed.ts";
import {
  ed25519SignerFromSecret,
  schnorrSignerFromSecret,
  secp256k1SignerFromSecret,
  secretKeyFromBytes,
} from "../../src/sign/index.ts";
import { deriveEd25519FromSeed } from "../../src/slip10/index.ts";

const root = join(import.meta.dirname, "../../../../vectors");

const TREZOR = JSON.parse(readFileSync(join(root, "bip39/trezor.json"), "utf8")) as {
  english: Array<[string, string, string]>;
};
const BIP39 = JSON.parse(readFileSync(join(root, "core/bip39.json"), "utf8")) as {
  cases: Array<{
    input?: string;
    entropy?: string;
    mnemonic?: string;
    passphrase?: string;
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

/** Run `f`, returning the thrown domain error code; sentinels keep assertions unconditional. */
function codeOf(f: () => unknown): string {
  try {
    f();
  } catch (error) {
    if (error instanceof DeriveError || error instanceof SignError || error instanceof VaultError) {
      return error.code;
    }
    return "<non-domain error thrown>";
  }
  return "<no error thrown>";
}

/** Map a thrown domain error code through `table` so runners assert shared vector codes. */
function mappedCode(table: Record<string, string>, f: () => unknown): string {
  const code = codeOf(f);
  return table[code] ?? `<unmapped ${code}>`;
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
// Wrong-length secrets fail inside secretKeyFromBytes (invalid_key → input); in-range
// length but out-of-range scalar fails inside the signer (invalid_key → crypto).
const secp256k1LenErrors = secp256k1KeyErrors.filter((c) => c.privateKey.length !== 64);
const secp256k1ScalarErrors = secp256k1KeyErrors.filter((c) => c.privateKey.length === 64);
const secp256k1DigestErrors = secp256k1Normalized.filter(
  (c) => c.error !== undefined && c.digest !== "",
);

const ZERO_AUX = "0".repeat(64);
// SchnorrSigner signs with zero aux by design; rows with a non-zero auxRand are
// verify-only on this API (signing coverage lives in the Rust runner).
const bip340Sign = BIP340.cases
  .filter((c) => c.secretKey !== undefined && c.auxRand === ZERO_AUX)
  .map((c) => ({ ...c, secretKey: c.secretKey ?? "" }));
const bip340Keyed = BIP340.cases
  .filter((c) => c.secretKey !== undefined)
  .map((c) => ({ ...c, secretKey: c.secretKey ?? "" }));

const ed25519Sign = ED25519.cases.filter((c) => c.valid);
const ed25519VerifyFalse = ED25519.cases.filter((c) => !c.valid);

describe("vectors/bip39/trezor.json", () => {
  test("entropy → mnemonic and mnemonic → seed (passphrase TREZOR)", () => {
    expect(TREZOR.english.length).toBeGreaterThan(0);
    for (const [entropy, mnemonic, seed] of TREZOR.english) {
      const wallet = walletFromEntropy(hexToBytes(entropy), "TREZOR");
      expect(wallet.mnemonic()).toBe(mnemonic);
      expect(bytesToHex(walletSeedBytes(wallet))).toBe(seed);
      wallet.dispose();

      const rebuilt = walletFromMnemonic(mnemonic, "TREZOR");
      expect(bytesToHex(walletSeedBytes(rebuilt))).toBe(seed);
      rebuilt.dispose();
    }
  });
});

describe("vectors/core/bip39.json", () => {
  test("entropy → mnemonic, seed and word count", () => {
    for (const c of bip39EntropyCases) {
      const wallet = walletFromEntropy(hexToBytes(c.entropy), c.passphrase);
      expect(wallet.mnemonic()).toBe(c.mnemonic);
      expect(wallet.wordCount).toBe(c.wordCount);
      expect(bytesToHex(walletSeedBytes(wallet))).toBe(c.seed);
      wallet.dispose();

      const rebuilt = walletFromMnemonic(c.mnemonic, c.passphrase);
      expect(bytesToHex(walletSeedBytes(rebuilt))).toBe(c.seed);
      rebuilt.dispose();
    }
  });

  test("whitespace normalization", () => {
    for (const c of bip39Normalize) {
      const wallet = walletFromMnemonic(c.input);
      expect(wallet.mnemonic()).toBe(c.mnemonic);
      wallet.dispose();
    }
  });

  test("invalid phrases share the error codes", () => {
    for (const c of bip39PhraseErrors) {
      expect(codeOf(() => walletFromMnemonic(c.input))).toBe(c.error);
    }
  });

  test("invalid entropy lengths share the error codes", () => {
    for (const c of bip39EntropyErrors) {
      expect(codeOf(() => walletFromEntropy(hexToBytes(c.entropy)))).toBe(c.error);
    }
  });
});

describe("vectors/core/bip32.json", () => {
  test("derive secp256k1 keys", () => {
    for (const c of bip32Valid) {
      const wallet = walletFromMnemonic(c.mnemonic, c.passphrase);
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
      const wallet = walletFromMnemonic(c.mnemonic, c.passphrase);
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
      const wallet = walletFromMnemonic(c.mnemonic, c.passphrase);
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
  test("32-byte secret round-trips through SecretKey32", () => {
    for (const c of secretKeyValid) {
      const key = secretKeyFromBytes(hexToBytes(c.input));
      expect(bytesToHex(key.toBytes())).toBe(c.output);
      key.dispose();
    }
  });

  test("wrong lengths share the error codes", () => {
    const map = { invalid_key: "input" };
    for (const c of secretKeyInvalid) {
      expect(mappedCode(map, () => secretKeyFromBytes(hexToBytes(c.input)))).toBe(c.error);
    }
  });
});

describe("vectors/core/secp256k1-ecdsa.json", () => {
  test("sign + public keys + verify (KAT and bitcoinjs fixtures)", () => {
    for (const c of secp256k1Sign) {
      const secret = secretKeyFromBytes(hexToBytes(c.privateKey));
      const signer = secp256k1SignerFromSecret(secret);
      const digest = hexToBytes(c.digest);
      expect(bytesToHex(signer.compressedPublicKey())).toBe(c.compressedPublicKey);
      expect(bytesToHex(signer.uncompressedPublicKey())).toBe(c.uncompressedPublicKey);
      const out = signer.signPrehashRecoverable(digest);
      expect(bytesToHex(out.signature)).toBe(c.signature);
      expect(out.v).toBe(c.recovery);
      expect(bytesToHex(signer.signPrehashDer(digest).der)).toBe(c.signatureDer);
      expect(signer.verifyPrehash(digest, out.signature)).toBe(true);
      signer.dispose();
      secret.dispose();
    }
  });

  test("tampered signatures verify false", () => {
    for (const c of secp256k1VerifyFalse) {
      const secret = secretKeyFromBytes(hexToBytes(c.privateKey));
      const signer = secp256k1SignerFromSecret(secret);
      expect(signer.verifyPrehash(hexToBytes(c.digest), hexToBytes(c.signature))).toBe(false);
      signer.dispose();
      secret.dispose();
    }
  });

  test("invalid keys share the error codes", () => {
    const lenMap = { invalid_key: "input" };
    const scalarMap = { invalid_key: "crypto" };
    for (const c of secp256k1LenErrors) {
      expect(mappedCode(lenMap, () => secretKeyFromBytes(hexToBytes(c.privateKey)))).toBe(c.error);
    }
    for (const c of secp256k1ScalarErrors) {
      expect(
        mappedCode(scalarMap, () =>
          secp256k1SignerFromSecret(secretKeyFromBytes(hexToBytes(c.privateKey))),
        ),
      ).toBe(c.error);
    }
  });

  test("wrong-length digests share the error codes", () => {
    const map = { invalid_message: "input" };
    for (const c of secp256k1DigestErrors) {
      const secret = secretKeyFromBytes(hexToBytes(c.privateKey));
      const signer = secp256k1SignerFromSecret(secret);
      expect(mappedCode(map, () => signer.signPrehashRecoverable(hexToBytes(c.digest)))).toBe(
        c.error,
      );
      signer.dispose();
      secret.dispose();
    }
  });
});

describe("vectors/core/bip340.json", () => {
  test("zero-aux rows sign deterministically", () => {
    for (const c of bip340Sign) {
      const secret = secretKeyFromBytes(hexToBytes(c.secretKey));
      const signer = schnorrSignerFromSecret(secret);
      expect(bytesToHex(signer.xonlyPublicKey())).toBe(c.publicKey);
      const sig = signer.sign(hexToBytes(c.message));
      expect(bytesToHex(sig.signature)).toBe(c.signature);
      signer.dispose();
      secret.dispose();
    }
  });

  // Rows without a secret key cannot be exercised here: the public API has no
  // verify-by-pubkey schnorr entry point (verify-by-pubkey coverage lives in the Rust runner).
  test("keyed rows verify to the expected boolean", () => {
    for (const c of bip340Keyed) {
      const secret = secretKeyFromBytes(hexToBytes(c.secretKey));
      const signer = schnorrSignerFromSecret(secret);
      expect(bytesToHex(signer.xonlyPublicKey())).toBe(c.publicKey);
      const ok = ((): boolean => {
        try {
          return signer.verify(hexToBytes(c.message), hexToBytes(c.signature));
        } catch {
          return false;
        }
      })();
      expect(ok).toBe(c.valid);
      signer.dispose();
      secret.dispose();
    }
  });
});

describe("vectors/core/ed25519.json", () => {
  test("RFC 8032 cases sign and verify", () => {
    for (const c of ed25519Sign) {
      const secret = secretKeyFromBytes(hexToBytes(c.secretKey));
      const signer = ed25519SignerFromSecret(secret);
      const message = hexToBytes(c.message);
      expect(bytesToHex(signer.publicKey())).toBe(c.publicKey);
      const out = signer.sign(message);
      expect(bytesToHex(out.signature)).toBe(c.signature);
      expect(signer.verify(message, out.signature)).toBe(true);
      signer.dispose();
      secret.dispose();
    }
  });

  test("tampered signatures verify false", () => {
    for (const c of ed25519VerifyFalse) {
      const secret = secretKeyFromBytes(hexToBytes(c.secretKey));
      const signer = ed25519SignerFromSecret(secret);
      const ok = ((): boolean => {
        try {
          return signer.verify(hexToBytes(c.message), hexToBytes(c.signature));
        } catch {
          return false;
        }
      })();
      expect(ok).toBe(false);
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
