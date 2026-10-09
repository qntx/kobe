import { readFileSync } from "node:fs";
import { join } from "node:path";

import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, test } from "vite-plus/test";

import { KobeError } from "../../src/core/error.ts";
import { walletSeed } from "../../src/core/wallet.ts";
import { NostrDeriver } from "../../src/nostr/index.ts";
import {
  derivePasswordKey,
  derivePrfKey,
  open,
  passkeyWallet,
  seal,
} from "../../src/vault/index.ts";

const root = join(import.meta.dirname, "../../../../vectors");

const SEAL = JSON.parse(readFileSync(join(root, "vault/seal.json"), "utf8")) as {
  cases: Array<{
    key: string;
    context: string;
    nonce?: string;
    plaintext?: string;
    sealed: string;
    error?: string;
  }>;
};
const PASSWORD_KEY = JSON.parse(readFileSync(join(root, "vault/password-key.json"), "utf8")) as {
  cases: Array<{
    password: string;
    salt: string;
    iterations: number;
    key?: string;
    error?: string;
  }>;
};
const PRF_KEY = JSON.parse(readFileSync(join(root, "vault/prf-key.json"), "utf8")) as {
  cases: Array<{ prf: string; info: string; key?: string; error?: string }>;
};
const PASSKEY_WALLET = JSON.parse(
  readFileSync(join(root, "vault/passkey-wallet.json"), "utf8"),
) as {
  cases: Array<{
    prf: string;
    mnemonic?: string;
    seed?: string;
    npub?: string;
    error?: string;
  }>;
};

/** Run `f`, returning the thrown `KobeError.code`; sentinels keep assertions unconditional. */
function codeOf(f: () => unknown): string {
  try {
    f();
    return "<no error thrown>";
  } catch (error) {
    return error instanceof KobeError ? error.code : "<non-KobeError thrown>";
  }
}

async function codeOfAsync(f: () => Promise<unknown>): Promise<string> {
  try {
    await f();
    return "<no error thrown>";
  } catch (error) {
    return error instanceof KobeError ? error.code : "<non-KobeError thrown>";
  }
}

/** RNG callback that yields exactly the vector nonce. */
const fixedRng = (nonce: Uint8Array) => (out: Uint8Array) => out.set(nonce);

const sealSuccess = SEAL.cases.filter(
  (c): c is (typeof SEAL.cases)[number] & { nonce: string; plaintext: string } =>
    c.nonce !== undefined && c.plaintext !== undefined,
);
const sealErrors = SEAL.cases.filter((c) => c.error !== undefined);
const passwordSuccess = PASSWORD_KEY.cases.filter((c) => c.key !== undefined);
const passwordErrors = PASSWORD_KEY.cases.filter((c) => c.error !== undefined);
const prfSuccess = PRF_KEY.cases.filter((c) => c.key !== undefined);
const prfErrors = PRF_KEY.cases.filter((c) => c.error !== undefined);
const passkeySuccess = PASSKEY_WALLET.cases.filter((c) => c.mnemonic !== undefined);
const passkeyErrors = PASSKEY_WALLET.cases.filter((c) => c.error !== undefined);

describe("vectors/vault/seal.json", () => {
  test("seal with the vector nonce reproduces the sealed bytes; open round-trips", () => {
    for (const c of sealSuccess) {
      const sealed = seal(
        hexToBytes(c.key),
        hexToBytes(c.plaintext),
        c.context,
        fixedRng(hexToBytes(c.nonce)),
      );
      expect(bytesToHex(sealed)).toBe(c.sealed);
      expect(bytesToHex(open(hexToBytes(c.key), sealed, c.context))).toBe(c.plaintext);
    }
  });

  test("failures share the error codes", () => {
    for (const c of sealErrors) {
      expect(codeOf(() => open(hexToBytes(c.key), hexToBytes(c.sealed), c.context))).toBe(c.error);
    }
  });
});

describe("vectors/vault/password-key.json", () => {
  test("PBKDF2-HMAC-SHA256 over NFKC(password)", async () => {
    const keys = await Promise.all(
      passwordSuccess.map(async (c) =>
        derivePasswordKey(c.password, hexToBytes(c.salt), c.iterations).then(bytesToHex),
      ),
    );
    expect(keys).toStrictEqual(passwordSuccess.map((c) => c.key));
  });

  test("invalid inputs share the error codes", async () => {
    const codes = await Promise.all(
      passwordErrors.map(async (c) =>
        codeOfAsync(async () => derivePasswordKey(c.password, hexToBytes(c.salt), c.iterations)),
      ),
    );
    expect(codes).toStrictEqual(passwordErrors.map((c) => c.error));
  });
});

describe("vectors/vault/prf-key.json", () => {
  test("HKDF-SHA256 with empty salt", () => {
    for (const c of prfSuccess) {
      expect(bytesToHex(derivePrfKey(hexToBytes(c.prf), c.info))).toBe(c.key);
    }
  });

  test("invalid inputs share the error codes", () => {
    for (const c of prfErrors) {
      expect(codeOf(() => derivePrfKey(hexToBytes(c.prf), c.info))).toBe(c.error);
    }
  });
});

describe("vectors/vault/passkey-wallet.json", () => {
  test("PRF → wallet mnemonic, seed and NIP-06 account 0 npub", () => {
    for (const c of passkeySuccess) {
      const wallet = passkeyWallet(hexToBytes(c.prf));
      expect(wallet.mnemonic()).toBe(c.mnemonic);
      expect(bytesToHex(walletSeed(wallet))).toBe(c.seed);
      const npub = new NostrDeriver(wallet).derive(0).npub();
      expect(npub).toBe(c.npub);
      wallet.dispose();
    }
  });

  test("invalid PRF lengths share the error codes", () => {
    for (const c of passkeyErrors) {
      expect(codeOf(() => passkeyWallet(hexToBytes(c.prf)))).toBe(c.error);
    }
  });
});
