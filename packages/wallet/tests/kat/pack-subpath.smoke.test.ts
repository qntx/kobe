import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { expect, test } from "vitest";
import { entry } from "../../tsdown.config.ts";

const root = resolve(import.meta.dirname, "../..");

function exportKey(entryKey: string): string {
  return entryKey === "index" ? "." : `./${entryKey}`;
}

const expectedExportKeys = new Set(Object.keys(entry).map(exportKey));

test("dist multi-entry artifacts exist after pack", () => {
  for (const name of Object.keys(entry)) {
    const mjs = resolve(root, "dist", `${name}.mjs`);
    const dts = resolve(root, "dist", `${name}.d.mts`);
    expect(existsSync(mjs), `missing ${mjs}`).toBe(true);
    expect(existsSync(dts), `missing ${dts}`).toBe(true);
  }
});

test("package.json exports map includes generated subpaths and @qntx/source", () => {
  const pkg = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8")) as {
    exports?: Record<string, unknown>;
  };
  expect(pkg.exports).toBeTypeOf("object");
  const exportsMap = pkg.exports ?? {};
  const keys = Object.keys(exportsMap).filter((k) => k !== "./package.json");
  expect(new Set(keys)).toEqual(expectedExportKeys);

  for (const [entryKey, src] of Object.entries(entry)) {
    const key = exportKey(entryKey);
    const value = exportsMap[key];
    expect(value, key).toBeTypeOf("object");
    const cond = value as Record<string, unknown>;
    expect(Object.keys(cond).toSorted(), key).toEqual(["@qntx/source", "default"]);
    expect(cond["@qntx/source"]).toBe(`./${src}`);
    expect(
      typeof cond.default === "string" && cond.default.endsWith(".mjs"),
      `${key} dist .mjs`,
    ).toBe(true);
  }
});

test("subpath modules resolve DeriveError / SignError", async () => {
  const hd = await import("../../dist/hd.mjs");
  const sign = await import("../../dist/sign.mjs");
  const rootMod = await import("../../dist/index.mjs");

  expect(hd.DeriveError).toBeTypeOf("function");
  expect(hd.isDeriveError).toBeTypeOf("function");
  expect(sign.SignError).toBeTypeOf("function");
  expect(sign.isSignError).toBeTypeOf("function");
  expect(rootMod.DeriveError).toBeTypeOf("function");
  expect("SignError" in rootMod).toBe(false);
});
