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
    const out = applyPackExports({ ".": "./dist/index.mjs" });
    expect(out["."]).toStrictEqual({
      types: "./dist/index.d.mts",
      import: "./dist/index.mjs",
      default: "./dist/index.mjs",
    });
  });

  test("leaves non-mjs strings and object exports unchanged", () => {
    const pkgJson = "./package.json";
    const index = { types: "./dist/index.d.mts", import: "./dist/index.mjs" };
    const out = applyPackExports({ "./package.json": pkgJson, ".": index });
    expect(out["./package.json"]).toBe(pkgJson);
    expect(out["."]).toBe(index);
  });
});

describe("package.json publish shape", () => {
  test("exports . with types and import paths", () => {
    expect(readPkg().exports["."]).toStrictEqual({
      types: "./dist/index.d.mts",
      import: "./dist/index.mjs",
      default: "./dist/index.mjs",
    });
  });

  test("exports ./package.json", () => {
    expect(readPkg().exports["./package.json"]).toBe("./package.json");
  });

  test("vite pack entries include src/index.ts", () => {
    const src = readFileSync(join(root, "vite.config.ts"), "utf8");
    expect(src).toContain('index: "src/index.ts"');
  });
});
