/// <reference types="node" />
/**
 * Writes `dist/kernel.manifest.json` after the kernel bundles: the protocol version, the vault
 * format, every external runtime dependency of `@qntx/wallet-kernel` with its bun.lock integrity,
 * and the SHA-256 of each bundle. Fails (non-zero exit) when a kernel dependency is not an exact
 * pin or disagrees with bun.lock — the manifest must never record a build the pins do not cover.
 *
 * Run from the package root: bun scripts/kernel-manifest.ts
 */
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { VAULT_FORMAT } from "../../wallet-kernel/src/vault/store.ts";
import { PROTOCOL_VERSION } from "../../wallet/src/protocol/index.ts";

export type KernelManifest = {
  readonly protocol: number;
  readonly vaultFormat: number;
  readonly libraries: ReadonlyArray<{
    readonly name: string;
    readonly version: string;
    readonly integrity: string;
  }>;
  readonly bundles: ReadonlyArray<{ readonly file: string; readonly sha256: string }>;
};

/**
 * Bun.lock is JSONC: generated entries carry trailing commas but no comments. Stripping commas
 * ahead of `}`/`]` makes it strict JSON; entry values are single-line, so the pattern cannot match
 * inside a string.
 */
export function parseLockfile(text: string): unknown {
  return JSON.parse(text.replaceAll(/,(\s*[}\]])/g, "$1")) as unknown;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function lockPackages(bunLock: unknown): Record<string, unknown> {
  const packages = isRecord(bunLock) ? bunLock["packages"] : undefined;
  return isRecord(packages) ? packages : {};
}

function stringMap(value: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (isRecord(value)) {
    for (const [key, entry] of Object.entries(value)) {
      if (typeof entry === "string") {
        out[key] = entry;
      }
    }
  }
  return out;
}

const EXACT_VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;

/**
 * Builds the manifest. `dependencies` is the kernel package's dependency table, `lockPackages` the
 * `packages` section of a parsed bun.lock, `bundles` the emitted worker files. A dependency
 * resolving to a `workspace:` path is bundled source, not a registry library — it is not listed
 * (its contract is pinned by `protocol`/`vaultFormat`). Everything else must be an exact pin that
 * resolves to itself with a recorded integrity.
 */
export function kernelManifest(input: {
  readonly dependencies: Readonly<Record<string, string>>;
  readonly lockPackages: Readonly<Record<string, unknown>>;
  readonly bundles: ReadonlyArray<{ readonly file: string; readonly bytes: Uint8Array }>;
  readonly protocol: number;
  readonly vaultFormat: number;
}): KernelManifest {
  const libraries: Array<{ name: string; version: string; integrity: string }> = [];
  const entries = Object.entries(input.dependencies).toSorted(([a], [b]) => a.localeCompare(b));
  for (const [name, spec] of entries) {
    if (!EXACT_VERSION.test(spec)) {
      throw new Error(`${name}: kernel dependencies must be exact versions, got "${spec}"`);
    }
    const entry = input.lockPackages[name];
    const resolvedField: unknown = Array.isArray(entry) ? entry[0] : undefined;
    const integrity: unknown = Array.isArray(entry) ? entry[3] : undefined;
    if (typeof resolvedField !== "string") {
      throw new TypeError(`${name}: not resolved in bun.lock`);
    }
    const resolved = resolvedField.slice(name.length + 1);
    if (resolved.startsWith("workspace:")) {
      continue;
    }
    if (resolved !== spec) {
      throw new Error(`${name}: pinned ${spec} but bun.lock resolves ${resolved}`);
    }
    if (typeof integrity !== "string" || integrity.length === 0) {
      throw new Error(`${name}: bun.lock records no integrity`);
    }
    libraries.push({ name, version: spec, integrity });
  }
  return {
    protocol: input.protocol,
    vaultFormat: input.vaultFormat,
    libraries,
    bundles: input.bundles.map(({ file, bytes }) => ({
      file,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    })),
  };
}

if (import.meta.main) {
  const packageDir = join(import.meta.dirname, "..");
  const root = join(packageDir, "..", "..");
  const kernelPkg: unknown = JSON.parse(
    readFileSync(join(root, "packages/wallet-kernel/package.json"), "utf8"),
  );
  const manifest = kernelManifest({
    dependencies: stringMap(isRecord(kernelPkg) ? kernelPkg["dependencies"] : undefined),
    lockPackages: lockPackages(parseLockfile(readFileSync(join(root, "bun.lock"), "utf8"))),
    bundles: ["kernel.worker.js", "kernel.node.js"].map((file) => ({
      file,
      bytes: readFileSync(join(packageDir, "dist", file)),
    })),
    protocol: PROTOCOL_VERSION,
    vaultFormat: VAULT_FORMAT,
  });
  const out = join(packageDir, "dist", "kernel.manifest.json");
  writeFileSync(out, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`wrote ${out}`);
}
