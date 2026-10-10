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
    const out = applyPackExports({ "./core": "./dist/core.mjs" });
    expect(out["./core"]).toStrictEqual({
      types: "./dist/core.d.mts",
      import: "./dist/core.mjs",
      default: "./dist/core.mjs",
    });
  });

  test("leaves non-mjs strings and object exports unchanged", () => {
    const pkgJson = "./package.json";
    const core = { types: "./dist/core.d.mts", import: "./dist/core.mjs" };
    const out = applyPackExports({ "./package.json": pkgJson, "./core": core });
    expect(out["./package.json"]).toBe(pkgJson);
    expect(out["./core"]).toBe(core);
  });
});

describe("package.json publish shape", () => {
  test("is subpath-only: ./core, ./evm, ./nostr, ./vault, no package root", () => {
    const pkg = readPkg();
    expect(pkg.exports["."]).toBeUndefined();
    for (const subpath of ["./core", "./evm", "./nostr", "./vault"] as const) {
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

  test("vite pack entries include the core, evm and nostr indexes", () => {
    const src = readFileSync(join(root, "vite.config.ts"), "utf8");
    expect(src).toContain('core: "src/core/index.ts"');
    expect(src).toContain('evm: "src/evm/index.ts"');
    expect(src).toContain('nostr: "src/nostr/index.ts"');
  });
});
