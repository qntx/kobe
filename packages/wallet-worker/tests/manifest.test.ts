import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vite-plus/test";

import { VAULT_FORMAT } from "../../wallet-kernel/src/vault/store.ts";
import { PROTOCOL_VERSION } from "../../wallet/src/protocol/index.ts";
import { kernelManifest, parseLockfile } from "../scripts/kernel-manifest.ts";

const packageDir = join(import.meta.dirname, "..");
const root = join(packageDir, "..", "..");

const kernelPkg = JSON.parse(
  readFileSync(join(root, "packages/wallet-kernel/package.json"), "utf8"),
) as { dependencies: Record<string, string> };
const lockPackages = ((
  parseLockfile(readFileSync(join(root, "bun.lock"), "utf8")) as { packages?: unknown }
).packages ?? {}) as Record<string, unknown>;

const bundles = [
  { file: "kernel.worker.js", bytes: new Uint8Array([0xde, 0xad]) },
  { file: "kernel.node.js", bytes: new Uint8Array([0xbe, 0xef]) },
];

describe("kernel manifest", () => {
  it("records the source constants, pinned versions, integrities and bundle hashes", () => {
    const manifest = kernelManifest({
      dependencies: kernelPkg.dependencies,
      lockPackages,
      bundles,
      protocol: PROTOCOL_VERSION,
      vaultFormat: VAULT_FORMAT,
    });
    expect(manifest.protocol).toBe(PROTOCOL_VERSION);
    expect(manifest.vaultFormat).toBe(VAULT_FORMAT);
    // Every external kernel dependency is listed once, sorted by name, pinned version and a
    // sha512 integrity; the workspace package @qntx/wallet is bundled source, not a library.
    expect(manifest.libraries.map(({ name }) => name)).toStrictEqual(
      Object.keys(kernelPkg.dependencies)
        .filter((name) => name !== "@qntx/wallet")
        .toSorted((a, b) => a.localeCompare(b)),
    );
    for (const lib of manifest.libraries) {
      expect(lib.version).toBe(kernelPkg.dependencies[lib.name]);
      expect(lib.integrity).toMatch(/^sha512-/);
    }
    expect(manifest.bundles).toStrictEqual(
      bundles.map(({ file, bytes }) => ({
        file,
        sha256: createHash("sha256").update(bytes).digest("hex"),
      })),
    );
  });

  it("rejects a dependency that is not exactly pinned", () => {
    expect(() =>
      kernelManifest({
        dependencies: { ...kernelPkg.dependencies, "@qntx/nostr": "^0.14.0" },
        lockPackages,
        bundles,
        protocol: PROTOCOL_VERSION,
        vaultFormat: VAULT_FORMAT,
      }),
    ).toThrow(/exact versions/);
  });

  it("rejects a pin that disagrees with bun.lock", () => {
    expect(() =>
      kernelManifest({
        dependencies: { ...kernelPkg.dependencies, "@qntx/nostr": "0.14.1" },
        lockPackages,
        bundles,
        protocol: PROTOCOL_VERSION,
        vaultFormat: VAULT_FORMAT,
      }),
    ).toThrow(/bun.lock resolves/);
  });
});
