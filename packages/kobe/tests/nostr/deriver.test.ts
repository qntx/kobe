import { inspect } from "node:util";

import { describe, expect, test } from "vite-plus/test";

import { KobeError, Wallet } from "../../src/core/index.ts";
import { NostrDeriver } from "../../src/nostr/index.ts";

const TV1_MNEMONIC =
  "leader monkey parrot ring guide accident before fence cannon height naive bean";

/** Run `f`, returning the thrown `KobeError.code`; sentinels keep assertions unconditional. */
function codeOf(f: () => unknown): string {
  try {
    f();
  } catch (error) {
    return error instanceof KobeError ? error.code : "<non-KobeError thrown>";
  }
  return "<no error thrown>";
}

describe("NostrDeriver", () => {
  test("deriveMany agrees with derive for every index", () => {
    const w = Wallet.fromMnemonic(TV1_MNEMONIC);
    const d = new NostrDeriver(w);
    const batch = d.deriveMany(0, 3);
    for (const [i, account] of batch.entries()) {
      const single = d.derive(i);
      expect(account.npub()).toBe(single.npub());
      expect(account.path).toBe(single.path);
      single.dispose();
    }
    for (const a of batch) {
      a.dispose();
    }
    w.dispose();
  });

  test("deriveMany rejects a u32 overflow with input", () => {
    const w = Wallet.fromMnemonic(TV1_MNEMONIC);
    expect(codeOf(() => new NostrDeriver(w).deriveMany(0xff_ff_ff_ff, 2))).toBe("input");
    w.dispose();
  });

  test("deriveAt accepts an arbitrary path", () => {
    const w = Wallet.fromMnemonic(TV1_MNEMONIC);
    const a = new NostrDeriver(w).deriveAt("m/44'/1237'/7'/0/0");
    expect(a.path).toBe("m/44'/1237'/7'/0/0");
    a.dispose();
    w.dispose();
  });

  test("passphrase changes derivation", () => {
    const a = new NostrDeriver(Wallet.fromMnemonic(TV1_MNEMONIC)).derive(0);
    const w = Wallet.fromMnemonic(TV1_MNEMONIC, "TREZOR");
    const b = new NostrDeriver(w).derive(0);
    expect(a.npub()).not.toBe(b.npub());
    a.dispose();
    b.dispose();
    w.dispose();
  });

  test("nsec is redacted; account accessors throw input after dispose", () => {
    const w = Wallet.fromMnemonic(TV1_MNEMONIC);
    const a = new NostrDeriver(w).derive(0);
    const nsec = a.nsec();
    const skHex = a.privateKeyHex();
    // `util.inspect` hides `#inner`'s private field and `#nsec`.
    expect(inspect(a)).not.toContain(nsec);
    expect(inspect(a)).not.toContain(skHex);
    expect(JSON.stringify(a)).not.toContain(nsec);
    a.dispose();
    a.dispose();
    for (const f of [() => a.nsec(), () => a.privateKeyBytes()]) {
      expect(codeOf(f)).toBe("input");
    }
    w.dispose();
  });

  test("deriving from a disposed wallet throws input", () => {
    const w = Wallet.fromMnemonic(TV1_MNEMONIC);
    const d = new NostrDeriver(w);
    w.dispose();
    expect(codeOf(() => d.derive(0))).toBe("input");
  });
});
