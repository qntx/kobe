import { utf8ToBytes } from "@noble/hashes/utils.js";
import { bech32 } from "@scure/base";
import { describe, expect, it } from "vite-plus/test";

import { Nip49Error } from "@qntx/nostr/nips/nip49";
import type { Scrypt } from "@qntx/nostr/nips/nip49";

import { KernelError } from "../src/errors.ts";
import type { KernelErrorCode } from "../src/errors.ts";
import { secretKeyFromNcryptsec } from "../src/modules/nostr/pool.ts";

// NIP-49 spec vector: password "nostr", logN 16.
const NIP49_NCRYPTSEC =
  "ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p";

function payload(encoded: string): Uint8Array {
  return new Uint8Array(bech32.fromWords(bech32.decode(encoded, 5000).words));
}

function reencode(mutated: Uint8Array): string {
  return bech32.encode("ncryptsec", bech32.toWords(mutated), 5000);
}

/** The KernelError code an async call settles with. */
async function codeOf(promise: Promise<unknown>): Promise<KernelErrorCode | undefined> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof KernelError) {
      return error.code;
    }
    throw error;
  }
  return undefined;
}

/** A scrypt stub that records invocations — proves shape/policy checks run before it. */
function spyingScrypt(calls: { count: number }, result?: () => Promise<Uint8Array>): Scrypt {
  return async (_password, _salt, params) => {
    calls.count++;
    return result === undefined ? new Uint8Array(params.dkLen) : result();
  };
}

describe("secretKeyFromNcryptsec", () => {
  it("decrypts the NIP-49 vector", { timeout: 30_000 }, async () => {
    const key = await secretKeyFromNcryptsec(NIP49_NCRYPTSEC, utf8ToBytes("nostr"), 20);
    expect(key).toHaveLength(32);
  });

  it("rejects malformed input with invalid-input and never runs scrypt", async () => {
    const calls = { count: 0 };
    const scrypt = spyingScrypt(calls);
    const wrongPrefix = bech32.encode("nsec", bech32.toWords(payload(NIP49_NCRYPTSEC)), 5000);
    for (const bad of ["ncryptsec1!!", reencode(new Uint8Array(10)), wrongPrefix]) {
      // oxlint-disable-next-line eslint/no-await-in-loop -- sequential malformed inputs
      await expect(
        codeOf(secretKeyFromNcryptsec(bad, utf8ToBytes("pw"), 20, scrypt)),
      ).resolves.toBe("invalid-input");
    }
    const badVersion = payload(NIP49_NCRYPTSEC);
    badVersion[0] = 0x03;
    await expect(
      codeOf(secretKeyFromNcryptsec(reencode(badVersion), utf8ToBytes("pw"), 20, scrypt)),
    ).resolves.toBe("invalid-input");
    expect(calls.count).toBe(0);
  });

  it("rejects logN above the policy max with unsupported before scrypt", async () => {
    const calls = { count: 0 };
    const scrypt = spyingScrypt(calls);
    const overLimit = payload(NIP49_NCRYPTSEC);
    overLimit[1] = 19; // logN 19 with a policy cap of 18
    await expect(
      codeOf(secretKeyFromNcryptsec(reencode(overLimit), utf8ToBytes("pw"), 18, scrypt)),
    ).resolves.toBe("unsupported");
    expect(calls.count).toBe(0);
  });

  it("maps a wrong password to wrong-password", { timeout: 30_000 }, async () => {
    await expect(
      codeOf(secretKeyFromNcryptsec(NIP49_NCRYPTSEC, utf8ToBytes("nope"), 20)),
    ).resolves.toBe("wrong-password");
  });

  it("maps a scrypt RangeError (allocation failure) to unavailable", async () => {
    // oxlint-disable-next-line typescript/require-await -- the Scrypt contract is async
    const scrypt: Scrypt = async () => {
      throw new RangeError("allocation failed");
    };
    // nip49 wraps kdf failures in Nip49Error with the original as cause.
    await expect(
      codeOf(secretKeyFromNcryptsec(NIP49_NCRYPTSEC, utf8ToBytes("nostr"), 20, scrypt)),
    ).resolves.toBe("unavailable");
  });

  it("maps other decrypt failures to wrong-password", async () => {
    // oxlint-disable-next-line typescript/require-await -- the Scrypt contract is async
    const scrypt: Scrypt = async () => {
      throw new Nip49Error("odd failure");
    };
    await expect(
      codeOf(secretKeyFromNcryptsec(NIP49_NCRYPTSEC, utf8ToBytes("nostr"), 20, scrypt)),
    ).resolves.toBe("wrong-password");
  });
});
