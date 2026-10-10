import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, test } from "vite-plus/test";

import { applyPackExports } from "../vite.config.ts";

const root = join(import.meta.dirname, "..");

type Pkg = {
  exports: Record<string, unknown>;
};

function readPkg(): Pkg {
  return JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as Pkg;
}

describe("applyPackExports", () => {
  test("maps a .mjs string export to types/import/default", () => {
    const out = applyPackExports({ "./hd": "./dist/hd.mjs" });
    expect(out["./hd"]).toStrictEqual({
      types: "./dist/hd.d.mts",
      import: "./dist/hd.mjs",
      default: "./dist/hd.mjs",
    });
  });

  test("leaves non-mjs strings and object exports unchanged", () => {
    const pkgJson = "./package.json";
    const hd = { types: "./dist/hd.d.mts", import: "./dist/hd.mjs" };
    const out = applyPackExports({ "./package.json": pkgJson, "./hd": hd });
    expect(out["./package.json"]).toBe(pkgJson);
    expect(out["./hd"]).toBe(hd);
  });
});

describe("package.json publish shape", () => {
  test("is subpath-only: every entry maps to its dist file, no package root", () => {
    const pkg = readPkg();
    expect(pkg.exports["."]).toBeUndefined();
    for (const subpath of [
      "./btc",
      "./evm",
      "./evm/rlp",
      "./hd",
      "./hd/camouflage",
      "./hd/raw-seed",
      "./hd/wordlists",
      "./nostr",
      "./sign",
      "./svm",
      "./vault",
    ] as const) {
      const name = subpath.slice(2);
      expect(pkg.exports[subpath]).toStrictEqual({
        types: `./dist/${name}.d.mts`,
        import: `./dist/${name}.mjs`,
        default: `./dist/${name}.mjs`,
      });
    }
  });

  test("exports ./package.json", () => {
    expect(readPkg().exports["./package.json"]).toBe("./package.json");
  });

  test("vite pack entries cover every published subpath", () => {
    const src = readFileSync(join(root, "vite.config.ts"), "utf8");
    for (const entry of [
      'btc: "src/chains/btc/index.ts"',
      'evm: "src/chains/evm/index.ts"',
      '"evm/rlp": "src/chains/evm/rlp.ts"',
      'hd: "src/hd/index.ts"',
      '"hd/camouflage": "src/hd/camouflage.ts"',
      '"hd/raw-seed": "src/hd/raw-seed.ts"',
      '"hd/wordlists": "src/hd/wordlists.ts"',
      'nostr: "src/chains/nostr/index.ts"',
      'sign: "src/sign/index.ts"',
      'svm: "src/chains/svm/index.ts"',
      'vault: "src/vault/index.ts"',
    ]) {
      expect(src).toContain(entry);
    }
  });
});
