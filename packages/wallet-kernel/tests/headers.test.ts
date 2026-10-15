import { describe, expect, it } from "vite-plus/test";

import {
  encodeHeader,
  parseDataKeyHeader,
  parseEntropyHeader,
  parseNostrKeyHeader,
  parsePasskeyFactorHeader,
  parsePasswordFactorHeader,
} from "../src/vault/headers.ts";
import type {
  DataKeyHeader,
  EntropyHeader,
  NostrKeyHeader,
  PasskeyFactorHeader,
  PasswordFactorHeader,
} from "../src/vault/headers.ts";
import { kernelError } from "./helpers.ts";

const entropy: EntropyHeader = {
  walletId: "6e0d11a50c03aa4f",
  origin: "passkey",
  words: 12,
  backedUp: false,
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
  createdAt: 1_767_225_600_000,
};

const dataKey: DataKeyHeader = { purpose: "meowl-messages", createdAt: 0 };

const passwordFactor: PasswordFactorHeader = {
  salt: "ABEiM0RVZneImaq7zN3u_w",
  iterations: 600_000,
  createdAt: 1_767_225_600_000,
};

const passkeyFactor: PasskeyFactorHeader = {
  credentialId: "3q2-78r-",
  createdAt: 1_767_225_600_000,
};

describe("header round trip", () => {
  it("entropy", () => {
    expect(parseEntropyHeader(encodeHeader(entropy))).toStrictEqual(entropy);
  });

  it("nostr-key derived and standalone", () => {
    expect(parseNostrKeyHeader(encodeHeader(nostrDerived))).toStrictEqual(nostrDerived);
    expect(parseNostrKeyHeader(encodeHeader(nostrStandalone))).toStrictEqual(nostrStandalone);
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
    expect(kernelError(() => parseEntropyHeader(JSON.stringify({ ...entropy, backedUp: 0 })))).toBe(
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

  it("derived nostr key missing groupIndex", () => {
    const { groupIndex: _omitted, ...withoutGroupIndex } = nostrDerived;
    expect(kernelError(() => parseNostrKeyHeader(JSON.stringify(withoutGroupIndex)))).toBe(
      "integrity",
    );
  });

  it("iterations other than 600000", () => {
    expect(
      kernelError(() =>
        parsePasswordFactorHeader(JSON.stringify({ ...passwordFactor, iterations: 599_999 })),
      ),
    ).toBe("integrity");
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
