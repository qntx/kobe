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

const KOBE = {
  path: "packages/kobe/package.json",
  pkg: { name: "@qntx/kobe", version: "3.4.0" },
};

const KOBE_NATIVE = {
  path: "packages/kobe-native/package.json",
  pkg: {
    name: "@qntx/kobe-native",
    version: "3.4.0",
    peerDependencies: { "@qntx/kobe": "^3.4.0" } as Record<string, string>,
    devDependencies: { "@qntx/kobe": "3.4.0" } as Record<string, string>,
  },
};

const PACKAGES = [KOBE, KOBE_NATIVE];

describe("check-version", () => {
  test("accepts synced versions", () => {
    expect(checkVersion(PACKAGES, PARSED, CARGO_TOML)).toStrictEqual([]);
  });

  test("rejects a package.json mismatch", () => {
    const errors = checkVersion(
      [KOBE, { ...KOBE_NATIVE, pkg: { ...KOBE_NATIVE.pkg, version: "3.4.1" } }],
      PARSED,
      CARGO_TOML,
    );
    expect(errors).toStrictEqual([
      "version mismatch: packages/kobe-native/package.json has 3.4.1, Cargo.toml has 3.4.0",
    ]);
  });

  test("rejects a peer range without a caret", () => {
    const pkg = structuredClone(KOBE_NATIVE.pkg);
    pkg.peerDependencies["@qntx/kobe"] = "3.4.0";
    const errors = checkVersion([KOBE, { ...KOBE_NATIVE, pkg }], PARSED, CARGO_TOML);
    expect(errors).toStrictEqual([
      'packages/kobe-native/package.json: peerDependencies["@qntx/kobe"] must be "^3.4.0", got "3.4.0"',
    ]);
  });

  test("rejects a dev range with a caret", () => {
    const pkg = structuredClone(KOBE_NATIVE.pkg);
    pkg.devDependencies["@qntx/kobe"] = "^3.4.0";
    const errors = checkVersion([KOBE, { ...KOBE_NATIVE, pkg }], PARSED, CARGO_TOML);
    expect(errors).toStrictEqual([
      'packages/kobe-native/package.json: devDependencies["@qntx/kobe"] must be "3.4.0", got "^3.4.0"',
    ]);
  });

  test("ignores ranges on external packages", () => {
    const pkg = structuredClone(KOBE_NATIVE.pkg);
    pkg.devDependencies["typescript"] = "^7.0.2";
    expect(checkVersion([KOBE, { ...KOBE_NATIVE, pkg }], PARSED, CARGO_TOML)).toStrictEqual([]);
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
