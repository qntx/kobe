import { describe, expect, test } from "vite-plus/test";

import { checkVersion } from "./check-version.ts";

const CARGO_TOML = `[workspace]
members = ["crates/*"]

[workspace.package]
version = "3.4.0"

[workspace.dependencies]
kobe-core = { version = "=3.4.0", path = "crates/kobe-core", default-features = false }
sha2 = "0.11"
`;

const PARSED = {
  workspace: {
    package: { version: "3.4.0" },
    dependencies: {
      "kobe-core": { version: "=3.4.0", path: "crates/kobe-core", "default-features": false },
      sha2: "0.11",
    },
  },
};

const WALLET = {
  path: "packages/wallet/package.json",
  pkg: { name: "@qntx/wallet", version: "0.4.0" },
};

const WALLET_CONSUMER = {
  path: "packages/wallet-consumer/package.json",
  pkg: {
    name: "@qntx/wallet-consumer",
    version: "0.1.0",
    peerDependencies: { "@qntx/wallet": "^0.4.0" } as Record<string, string>,
    devDependencies: { "@qntx/wallet": "0.4.0" } as Record<string, string>,
  },
};

const PACKAGES = [WALLET, WALLET_CONSUMER];

describe("check-version", () => {
  test("accepts npm versions that differ from the Cargo workspace version", () => {
    expect(checkVersion(PACKAGES, PARSED, CARGO_TOML)).toStrictEqual([]);
  });

  test("rejects a peer range without a caret", () => {
    const pkg = structuredClone(WALLET_CONSUMER.pkg);
    pkg.peerDependencies["@qntx/wallet"] = "0.4.0";
    const errors = checkVersion([WALLET, { ...WALLET_CONSUMER, pkg }], PARSED, CARGO_TOML);
    expect(errors).toStrictEqual([
      'packages/wallet-consumer/package.json: peerDependencies["@qntx/wallet"] must be "^0.4.0", got "0.4.0"',
    ]);
  });

  test("rejects a dev range with a caret", () => {
    const pkg = structuredClone(WALLET_CONSUMER.pkg);
    pkg.devDependencies["@qntx/wallet"] = "^0.4.0";
    const errors = checkVersion([WALLET, { ...WALLET_CONSUMER, pkg }], PARSED, CARGO_TOML);
    expect(errors).toStrictEqual([
      'packages/wallet-consumer/package.json: devDependencies["@qntx/wallet"] must be "0.4.0", got "^0.4.0"',
    ]);
  });

  test("ignores ranges on external packages", () => {
    const pkg = structuredClone(WALLET_CONSUMER.pkg);
    pkg.devDependencies["typescript"] = "^7.0.2";
    expect(checkVersion([WALLET, { ...WALLET_CONSUMER, pkg }], PARSED, CARGO_TOML)).toStrictEqual(
      [],
    );
  });

  test("rejects an internal dep not pinned to the workspace version", () => {
    const parsed = structuredClone(PARSED);
    parsed.workspace.dependencies["kobe-core"].version = "=3.3.0";
    const errors = checkVersion(PACKAGES, parsed, CARGO_TOML);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain("kobe-core");
  });

  test("rejects a third-party dep equal to the current version", () => {
    const toml = CARGO_TOML.replace('sha2 = "0.11"', 'sha2 = "3.4.0"');
    const parsed = structuredClone(PARSED);
    parsed.workspace.dependencies.sha2 = "3.4.0";
    const errors = checkVersion(PACKAGES, parsed, toml);
    expect(errors).toStrictEqual([
      'Cargo.toml: "3.4.0" appears 3 times, expected 2 ([workspace.package] plus internal path dependencies)',
    ]);
  });
});
