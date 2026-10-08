import { inspect } from "node:util";

import { describe, expect, test } from "vite-plus/test";

import { createDerivedAccount } from "../../src/core/account.ts";
import type { DerivedPublicKey } from "../../src/core/account.ts";
import { KobeError } from "../../src/core/index.ts";

const SK = new Uint8Array(32).fill(7);
const PK33 = new Uint8Array(33).fill(2);

function make() {
  return createDerivedAccount({
    path: "m/44'/60'/0'/0/0",
    privateKey: SK,
    publicKey: { kind: "secp256k1-compressed", bytes: PK33 },
    address: "0xABC",
  });
}

/** Run `f`, returning the thrown `KobeError.code`; sentinels keep assertions unconditional. */
function codeOf(f: () => unknown): string {
  try {
    f();
  } catch (error) {
    return error instanceof KobeError ? error.code : "<non-KobeError thrown>";
  }
  return "<no error thrown>";
}

const badInputs: Array<{
  privateKey: Uint8Array;
  publicKey: DerivedPublicKey;
}> = [
  {
    privateKey: new Uint8Array(31),
    publicKey: { kind: "secp256k1-compressed", bytes: PK33 },
  },
  {
    privateKey: SK,
    publicKey: { kind: "secp256k1-compressed", bytes: new Uint8Array(32) },
  },
];

describe("createDerivedAccount", () => {
  test("copies inputs; mutating sources does not leak in", () => {
    const sk = new Uint8Array(32).fill(9);
    const pk = new Uint8Array(33).fill(2);
    const a = createDerivedAccount({
      path: "m",
      privateKey: sk,
      publicKey: { kind: "secp256k1-compressed", bytes: pk },
      address: "x",
    });
    sk.fill(0);
    pk.fill(0);
    expect(a.privateKeyBytes()[0]).toBe(9);
    expect(a.publicKey.bytes[0]).toBe(2);
    a.dispose();
  });

  test("rejects a non-32-byte secret and a kind/length mismatch", () => {
    for (const bad of badInputs) {
      expect(
        codeOf(() =>
          createDerivedAccount({
            path: "m",
            privateKey: bad.privateKey,
            publicKey: bad.publicKey,
            address: "x",
          }),
        ),
      ).toBe("crypto");
    }
  });

  test("dispose wipes the secret; accessors throw input", () => {
    const a = make();
    a.dispose();
    a.dispose();
    for (const f of [() => a.privateKeyBytes(), () => a.privateKeyHex()]) {
      expect(codeOf(f)).toBe("input");
    }
  });

  test("toString / JSON / inspect redact the private key", () => {
    const a = make();
    const skHex = "07".repeat(32);
    expect(a.toString()).toContain("[REDACTED]");
    expect(a.toString()).not.toContain(skHex);
    expect(JSON.stringify(a)).not.toContain(skHex);
    expect(JSON.stringify(a)).toContain("0xABC");
    // `util.inspect` hides the `#sk` private field.
    expect(inspect(a)).not.toContain(skHex);
    a.dispose();
  });
});
