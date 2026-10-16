import { describe, expect, it } from "vite-plus/test";

import { encodeNostrKeyHeader, parseNostrKeyHeader } from "../src/modules/nostr/record.ts";
import type { NostrKeyHeader } from "../src/modules/nostr/record.ts";
import {
  encodeHeader,
  parseDataKeyHeader,
  parseEntropyHeader,
  parsePasskeyFactorHeader,
  parsePasswordFactorHeader,
} from "../src/vault/headers.ts";
import type {
  DataKeyHeader,
  EntropyHeader,
  PasskeyFactorHeader,
  PasswordFactorHeader,
} from "../src/vault/headers.ts";
import { kernelError } from "./helpers.ts";

const entropy: EntropyHeader = {
  walletId: "6e0d11a50c03aa4f",
  origin: "passkey",
  words: 12,
  backup: "none",
  createdAt: 1_767_225_600_000,
};

const nostrDerived: NostrKeyHeader = {
  publicKey: "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917",
  origin: "derived",
  walletId: "6e0d11a50c03aa4f",
  groupIndex: 0,
  createdAt: 1_767_225_600_000,
};

const nostrStandalone: NostrKeyHeader = {
  publicKey: nostrDerived.publicKey,
  origin: "generated",
  backedUp: false,
  createdAt: 1_767_225_600_000,
};

const nostrNip46: NostrKeyHeader = {
  publicKey: nostrDerived.publicKey,
  origin: "nip46-client",
  createdAt: 1_767_225_600_000,
};

const dataKey: DataKeyHeader = { purpose: "meowl-messages", createdAt: 0 };

const passwordFactor: PasswordFactorHeader = {
  salt: "ABEiM0RVZneImaq7zN3u_w",
  iterations: 600_000,
  publicKey: "PxLfxal_e43m4jpaNusYyCfYFXOkFoQAQ1lQI1s0HUM",
  createdAt: 1_767_225_600_000,
};

const passkeyFactor: PasskeyFactorHeader = {
  credentialId: "3q2-78r-",
  publicKey: "JqRYFT66Kmogg041szL7sSC6lKDj6VPKh-5HsP3DbAE",
  createdAt: 1_767_225_600_000,
};

describe("header round trip", () => {
  it("entropy", () => {
    expect(parseEntropyHeader(encodeHeader(entropy))).toStrictEqual(entropy);
  });

  it("nostr-key derived, standalone and nip46-client", () => {
    expect(parseNostrKeyHeader(encodeNostrKeyHeader(nostrDerived))).toStrictEqual(nostrDerived);
    expect(parseNostrKeyHeader(encodeNostrKeyHeader(nostrStandalone))).toStrictEqual(
      nostrStandalone,
    );
    expect(parseNostrKeyHeader(encodeNostrKeyHeader(nostrNip46))).toStrictEqual(nostrNip46);
  });

  it("data-key", () => {
    expect(parseDataKeyHeader(encodeHeader(dataKey))).toStrictEqual(dataKey);
  });

  it("factors", () => {
    expect(parsePasswordFactorHeader(encodeHeader(passwordFactor))).toStrictEqual(passwordFactor);
    expect(parsePasskeyFactorHeader(encodeHeader(passkeyFactor))).toStrictEqual(passkeyFactor);
  });
});

describe("header rejection", () => {
  it("extra key", () => {
    expect(kernelError(() => parseEntropyHeader(JSON.stringify({ ...entropy, extra: 1 })))).toBe(
      "integrity",
    );
  });

  it("missing key", () => {
    const { walletId: _omitted, ...withoutWalletId } = entropy;
    expect(kernelError(() => parseEntropyHeader(JSON.stringify(withoutWalletId)))).toBe(
      "integrity",
    );
  });

  it("wrong type", () => {
    expect(kernelError(() => parseEntropyHeader(JSON.stringify({ ...entropy, words: "12" })))).toBe(
      "integrity",
    );
    expect(kernelError(() => parseEntropyHeader(JSON.stringify({ ...entropy, backup: 0 })))).toBe(
      "integrity",
    );
  });

  it("uppercase walletId and publicKey", () => {
    expect(
      kernelError(() =>
        parseEntropyHeader(
          JSON.stringify({ ...entropy, walletId: entropy.walletId.toUpperCase() }),
        ),
      ),
    ).toBe("integrity");
    expect(
      kernelError(() =>
        parseNostrKeyHeader(
          JSON.stringify({
            ...nostrStandalone,
            publicKey: nostrStandalone.publicKey.toUpperCase(),
          }),
        ),
      ),
    ).toBe("integrity");
  });

  it("walletId or groupIndex on a non-derived nostr key", () => {
    expect(
      kernelError(() =>
        parseNostrKeyHeader(JSON.stringify({ ...nostrStandalone, walletId: entropy.walletId })),
      ),
    ).toBe("integrity");
    expect(
      kernelError(() => parseNostrKeyHeader(JSON.stringify({ ...nostrStandalone, groupIndex: 0 }))),
    ).toBe("integrity");
  });

  it("backedUp is required on standalone keys and forbidden elsewhere", () => {
    const { backedUp: _omitted, ...withoutBackedUp } = nostrStandalone;
    expect(kernelError(() => parseNostrKeyHeader(JSON.stringify(withoutBackedUp)))).toBe(
      "integrity",
    );
    expect(
      kernelError(() =>
        parseNostrKeyHeader(JSON.stringify({ ...nostrStandalone, backedUp: "yes" })),
      ),
    ).toBe("integrity");
    // Derived and nip46-client headers have an exact key set: backedUp is an unknown key.
    expect(
      kernelError(() => parseNostrKeyHeader(JSON.stringify({ ...nostrDerived, backedUp: true }))),
    ).toBe("integrity");
    expect(
      kernelError(() => parseNostrKeyHeader(JSON.stringify({ ...nostrNip46, backedUp: true }))),
    ).toBe("integrity");
  });

  it("an own key named after an Object.prototype member is still unknown", () => {
    // JSON.parse defines "__proto__" as an own enumerable key; every parser must reject it.
    const protoKeys = '{"__proto__":1,"constructor":1,"hasOwnProperty":1,"valueOf":1}';
    for (const parser of [
      parseEntropyHeader,
      parseDataKeyHeader,
      parsePasswordFactorHeader,
      parsePasskeyFactorHeader,
      parseNostrKeyHeader,
    ]) {
      expect(kernelError(() => parser(protoKeys))).toBe("integrity");
    }
    // The same own keys smuggled into an otherwise-valid header are rejected by the key count.
    for (const valid of [
      encodeHeader(entropy),
      encodeHeader(dataKey),
      encodeHeader(passwordFactor),
      encodeHeader(passkeyFactor),
      encodeNostrKeyHeader(nostrStandalone),
      encodeNostrKeyHeader(nostrDerived),
      encodeNostrKeyHeader(nostrNip46),
    ]) {
      const object = JSON.parse(valid) as Record<string, unknown>;
      const withProto = JSON.parse(protoKeys) as Record<string, unknown>;
      for (const parser of [
        parseEntropyHeader,
        parseDataKeyHeader,
        parsePasswordFactorHeader,
        parsePasskeyFactorHeader,
        parseNostrKeyHeader,
      ]) {
        expect(kernelError(() => parser(JSON.stringify({ ...object, ...withProto })))).toBe(
          "integrity",
        );
      }
    }
  });

  it("derived nostr key missing groupIndex", () => {
    const { groupIndex: _omitted, ...withoutGroupIndex } = nostrDerived;
    expect(kernelError(() => parseNostrKeyHeader(JSON.stringify(withoutGroupIndex)))).toBe(
      "integrity",
    );
  });

  it("iterations other than 600000 is unsupported; a non-integer is integrity", () => {
    // A well-formed header with different KDF parameters came from another build.
    expect(
      kernelError(() =>
        parsePasswordFactorHeader(JSON.stringify({ ...passwordFactor, iterations: 599_999 })),
      ),
    ).toBe("unsupported");
    expect(
      kernelError(() =>
        parsePasswordFactorHeader(JSON.stringify({ ...passwordFactor, iterations: 1_000_000 })),
      ),
    ).toBe("unsupported");
    expect(
      kernelError(() =>
        parsePasswordFactorHeader(JSON.stringify({ ...passwordFactor, iterations: 0.5 })),
      ),
    ).toBe("integrity");
    expect(
      kernelError(() =>
        parsePasswordFactorHeader(JSON.stringify({ ...passwordFactor, iterations: "600000" })),
      ),
    ).toBe("integrity");
  });

  it("bad factor publicKey and bad purpose", () => {
    // A factor publicKey must decode to exactly 32 bytes.
    expect(
      kernelError(() =>
        parsePasswordFactorHeader(JSON.stringify({ ...passwordFactor, publicKey: "AA" })),
      ),
    ).toBe("integrity");
    expect(
      kernelError(() =>
        parsePasskeyFactorHeader(JSON.stringify({ ...passkeyFactor, publicKey: "AA==" })),
      ),
    ).toBe("integrity");
    const { publicKey: _omitted, ...withoutPublicKey } = passkeyFactor;
    expect(kernelError(() => parsePasskeyFactorHeader(JSON.stringify(withoutPublicKey)))).toBe(
      "integrity",
    );
  });

  it("bad salt length and bad purpose", () => {
    expect(
      kernelError(() =>
        parsePasswordFactorHeader(JSON.stringify({ ...passwordFactor, salt: "AA" })),
      ),
    ).toBe("integrity");
    expect(
      kernelError(() => parseDataKeyHeader(JSON.stringify({ ...dataKey, purpose: "UPPER_CASE" }))),
    ).toBe("integrity");
    expect(
      kernelError(() =>
        parseDataKeyHeader(JSON.stringify({ ...dataKey, purpose: "x".repeat(33) })),
      ),
    ).toBe("integrity");
  });

  it("not JSON", () => {
    expect(kernelError(() => parsePasswordFactorHeader("{not json"))).toBe("integrity");
  });
});
