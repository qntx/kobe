/// <reference types="node" />
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

// The repo does not depend on @types/bun; declare the used surface.
declare const Bun: {
  JSONC: { parse: (text: string) => unknown };
};

type JsonObject = Record<string, unknown>;

function isRecord(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asRecord(value: unknown): JsonObject {
  return isRecord(value) ? value : {};
}

export type PackageEntry = { path: string; pkg: unknown };

/**
 * Consistency check: internal `@qntx/*` dependencies must be exact `<version>` pins in
 * dependencies, peerDependencies and devDependencies — a caret peer would let a different package
 * version slip in against a bundled kernel built for one protocol version — and every `workspaces`
 * entry in bun.lock must record the package.json version of its workspace directory. The private
 * workspace root is not passed in.
 */
export function checkVersion(packages: PackageEntry[], bunLock: unknown): string[] {
  const errors: string[] = [];

  const internalVersions = new Map<string, string>();
  for (const { pkg } of packages) {
    const { name, version } = asRecord(pkg);
    if (typeof name === "string" && typeof version === "string") {
      internalVersions.set(name, version);
    }
  }

  for (const { path, pkg } of packages) {
    const manifest = asRecord(pkg);
    const { version } = manifest;
    if (typeof version !== "string") {
      errors.push(`${path}: missing string "version"`);
      continue;
    }
    for (const section of ["dependencies", "peerDependencies", "devDependencies"] as const) {
      const deps = asRecord(manifest[section]);
      for (const [name, spec] of Object.entries(deps)) {
        const depVersion = internalVersions.get(name);
        if (depVersion === undefined) {
          continue;
        }
        if (spec !== depVersion) {
          errors.push(
            `${path}: ${section}["${name}"] must be "${depVersion}", got ${JSON.stringify(spec)}`,
          );
        }
      }
    }
  }

  // bun.lock mirrors each workspace manifest's `version` under `workspaces`
  // keyed by directory; drift means the lockfile refresh was skipped.
  const workspaces = asRecord(asRecord(bunLock)["workspaces"]);
  for (const { path, pkg } of packages) {
    const dir = path.slice(0, -"/package.json".length);
    const { version } = asRecord(pkg);
    const entry = workspaces[dir];
    if (entry === undefined) {
      errors.push(`bun.lock: missing workspaces["${dir}"] entry`);
      continue;
    }
    const lockVersion = asRecord(entry)["version"];
    if (lockVersion !== version) {
      errors.push(
        `bun.lock: workspaces["${dir}"] has version ${JSON.stringify(lockVersion)}, expected ${JSON.stringify(version)}`,
      );
    }
  }

  return errors;
}

if (import.meta.main) {
  // Only directories with a package.json are workspaces; bare leftovers may
  // exist under packages/.
  const packages: PackageEntry[] = readdirSync("packages", { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => join("packages", entry.name, "package.json"))
    .filter((path) => existsSync(path))
    .map((path) => ({ path, pkg: JSON.parse(readFileSync(path, "utf8")) as unknown }));
  const errors = checkVersion(packages, Bun.JSONC.parse(readFileSync("bun.lock", "utf8")));
  for (const error of errors) {
    console.error(`check-version: ${error}`);
  }
  if (errors.length > 0) {
    process.exitCode = 1;
  }
}
