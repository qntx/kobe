/// <reference types="node" />
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { basename, join } from "node:path";

type JsonObject = Record<string, unknown>;

const TIERS = new Set(["A", "B", "C"]);
const STATUSES = new Set(["stable", "ts-only", "planned", "n/a"]);

function isRecord(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asRecord(value: unknown): JsonObject {
  return isRecord(value) ? value : {};
}

function asStrings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

/** One side (ts or rust) of a capability entry: `null` or `{ module, tests }`. */
function sidePaths(side: unknown): { module: string | undefined; tests: string[] } {
  const record = asRecord(side);
  const { module } = record;
  return {
    module: typeof module === "string" ? module : undefined,
    tests: asStrings(record["tests"]),
  };
}

/**
 * Validates parity.json against the vectors/ tree. Returns error messages; an empty array means the
 * file is consistent.
 */
export function checkParity(
  parity: unknown,
  vectorFiles: string[],
  fileExists: (path: string) => boolean,
  readFile: (path: string) => string,
): string[] {
  const errors: string[] = [];
  const { capabilities } = asRecord(parity);
  if (!Array.isArray(capabilities)) {
    return ['parity.json: missing "capabilities" array'];
  }

  const seen = new Set<string>();
  const referencedVectors = new Set<string>();

  for (const item of capabilities) {
    const cap = asRecord(item);
    const { id: rawId } = cap;
    const id = typeof rawId === "string" ? rawId : "?";
    const label = `capability "${id}"`;

    if (typeof rawId !== "string" || rawId === "") {
      errors.push("capability without a string id");
    } else if (seen.has(id)) {
      errors.push(`${label}: duplicate id`);
    }
    seen.add(id);

    const { tier } = cap;
    if (typeof tier !== "string" || !TIERS.has(tier)) {
      errors.push(`${label}: tier must be one of A|B|C`);
    }
    const { status } = cap;
    if (typeof status !== "string" || !STATUSES.has(status)) {
      errors.push(`${label}: status must be one of stable|ts-only|planned|n/a`);
    } else {
      if (status === "n/a" && tier !== "C") {
        errors.push(`${label}: status "n/a" is only allowed for tier C`);
      }
      if (tier === "C" && status !== "n/a") {
        errors.push(`${label}: tier C must have status "n/a"`);
      }
    }

    const ts = sidePaths(cap["ts"]);
    const rust = sidePaths(cap["rust"]);
    const testFiles = [...ts.tests, ...rust.tests];

    for (const path of [ts.module, rust.module, ...testFiles]) {
      if (typeof path === "string" && !fileExists(path)) {
        errors.push(`${label}: referenced path does not exist: ${path}`);
      }
    }

    const vectors = asStrings(cap["vectors"]);
    for (const vector of vectors) {
      referencedVectors.add(vector);
      if (!fileExists(vector)) {
        errors.push(`${label}: vector file does not exist: ${vector}`);
        continue;
      }
      const needles = [vector, basename(vector)];
      const cited = testFiles.some((testFile) => {
        if (!fileExists(testFile)) {
          return false;
        }
        const content = readFile(testFile);
        return needles.some((needle) => content.includes(needle));
      });
      if (!cited) {
        errors.push(`${label}: vector ${vector} is not referenced by any of its test files`);
      }
    }

    if (status === "stable") {
      if (ts.tests.length === 0 || rust.tests.length === 0) {
        errors.push(`${label}: "stable" requires non-empty ts.tests and rust.tests`);
      }
      if (tier === "A" && vectors.length === 0) {
        errors.push(`${label}: tier A "stable" requires at least one vector file`);
      }
    }
  }

  for (const file of vectorFiles) {
    if (basename(file) === "README.md") {
      continue;
    }
    if (!referencedVectors.has(file)) {
      errors.push(`vector file is not referenced by any capability: ${file}`);
    }
  }

  return errors;
}

function listVectors(dir: string, prefix: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(prefix, entry.name);
    if (entry.isDirectory()) {
      out.push(...listVectors(join(dir, entry.name), path));
    } else {
      out.push(path);
    }
  }
  return out.toSorted();
}

if (import.meta.main) {
  const parity: unknown = JSON.parse(readFileSync("parity.json", "utf8"));
  const vectorFiles = existsSync("vectors") ? listVectors("vectors", "vectors") : [];
  const errors = checkParity(
    parity,
    vectorFiles,
    (path) => existsSync(path),
    (path) => readFileSync(path, "utf8"),
  );
  for (const error of errors) {
    console.error(`parity: ${error}`);
  }
  if (errors.length > 0) {
    process.exitCode = 1;
  }
}
