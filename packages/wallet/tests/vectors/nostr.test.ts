import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, test } from "vite-plus/test";

import { createNostrDeriver } from "../../src/chains/nostr/index.ts";
import { walletFromMnemonic } from "../../src/hd/index.ts";

const NIP06 = JSON.parse(
  readFileSync(join(import.meta.dirname, "../../../../vectors/nostr/nip06.json"), "utf8"),
) as {
  cases: Array<{
    mnemonic: string;
    passphrase?: string;
    account: number;
    path: string;
    privateKey: string;
    publicKey: string;
    nsec: string;
    npub: string;
  }>;
};

const cases = NIP06.cases.map((c) => ({ ...c, passphrase: c.passphrase ?? "" }));

describe("vectors/nostr/nip06.json", () => {
  test("derive NIP-06 accounts", () => {
    for (const c of cases) {
      const wallet = walletFromMnemonic(c.mnemonic, c.passphrase);
      const account = createNostrDeriver(wallet).derive(c.account);
      expect(account.path).toBe(c.path);
      expect(account.privateKeyHex()).toBe(c.privateKey);
      expect(account.publicKeyHex()).toBe(c.publicKey);
      expect(account.publicKey.kind).toBe("secp256k1-xonly");
      expect(account.nsec()).toBe(c.nsec);
      expect(account.npub()).toBe(c.npub);
      expect(account.address).toBe(c.npub);
      account.dispose();
      wallet.dispose();
    }
  });
});
