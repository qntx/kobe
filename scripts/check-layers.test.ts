import { describe, expect, test } from "vite-plus/test";

import { checkLayers, crateFromManifest } from "./check-layers.ts";
import type { CrateInfo } from "./check-layers.ts";

function crate(name: string, deps: string[], publish = true): CrateInfo {
  return { name, publish, deps };
}

describe("check-layers", () => {
  test("accepts the allowed edges", () => {
    const crates = [
      crate("kobe-core", []),
      crate("kobe-btc", ["kobe-core"]),
      crate("kobe", ["kobe-core", "kobe-btc"]),
      crate("kobe-cli", ["kobe"]),
    ];
    expect(checkLayers(crates)).toStrictEqual([]);
  });

  test("rejects a reverse edge", () => {
    const crates = [crate("kobe-core", ["kobe-btc"]), crate("kobe-btc", ["kobe-core"])];
    const errors = checkLayers(crates);
    expect(errors).toStrictEqual(["kobe-core: must not depend on kobe-btc"]);
  });

  test("rejects a chain crate depending on the umbrella", () => {
    const errors = checkLayers([crate("kobe-evm", ["kobe"])]);
    expect(errors).toStrictEqual(["kobe-evm: must not depend on kobe"]);
  });

  test("rejects tokio in a P-level crate", () => {
    const errors = checkLayers([crate("kobe-core", ["tokio"])]);
    expect(errors).toStrictEqual(["kobe-core: P-level crate must not depend on tokio"]);
  });

  test("rejects reqwest in a P-level crate", () => {
    const errors = checkLayers([crate("kobe-evm", ["reqwest"])]);
    expect(errors).toStrictEqual(["kobe-evm: P-level crate must not depend on reqwest"]);
  });

  test("allows reqwest in kobe-cli", () => {
    const errors = checkLayers([crate("kobe-cli", ["kobe", "reqwest"])]);
    expect(errors).toStrictEqual([]);
  });

  test("rejects tokio hidden in a target-specific dependency table", () => {
    const info = crateFromManifest(
      {
        package: { name: "kobe-core" },
        dependencies: {},
        target: { "cfg(unix)": { dependencies: { tokio: "1" } } },
      },
      "kobe-core",
    );
    expect(checkLayers([info])).toStrictEqual([
      "kobe-core: P-level crate must not depend on tokio",
    ]);
  });

  test("rejects a published crate depending on an unpublished one", () => {
    const crates = [crate("kobe", ["kobe-core", "kobe-cli"]), crate("kobe-cli", [], false)];
    const errors = checkLayers(crates);
    expect(errors).toStrictEqual(["kobe: published crate must not depend on kobe-cli"]);
  });

  test("rejects an unknown kobe-* crate", () => {
    const errors = checkLayers([crate("kobe-mystery", [])]);
    expect(errors).toStrictEqual(['unknown crate "kobe-mystery"']);
  });

  test("kobe-vault is P-level and may only depend on kobe-core", () => {
    expect(checkLayers([crate("kobe-vault", ["kobe-core"])])).toStrictEqual([]);
    expect(checkLayers([crate("kobe-vault", ["kobe-btc"])])).toStrictEqual([
      "kobe-vault: must not depend on kobe-btc",
    ]);
    expect(checkLayers([crate("kobe-vault", ["tokio"])])).toStrictEqual([
      "kobe-vault: P-level crate must not depend on tokio",
    ]);
  });

  test("kobe-vectors may depend on any crate", () => {
    const crates = [
      crate("kobe-core", []),
      crate("kobe-nostr", ["kobe-core"]),
      crate("kobe-vectors", ["kobe-core", "kobe-nostr", "kobe"], false),
    ];
    expect(checkLayers(crates)).toStrictEqual([]);
  });

  test("kobe-vectors is not a P-level crate", () => {
    const errors = checkLayers([crate("kobe-vectors", ["tokio"], false)]);
    expect(errors).toStrictEqual([]);
  });
});
