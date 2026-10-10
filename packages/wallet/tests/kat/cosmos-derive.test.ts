import { bech32 } from "@scure/base";
import { expect, test } from "vitest";
import {
  COSMOS_HUB,
  OSMOSIS,
  TERRA,
  cosmosChainConfig,
  createCosmosDeriver,
} from "../../src/chains/cosmos/index.ts";
import { walletFromMnemonic } from "../../src/hd/index.ts";

const ABANDON =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

test("gold: Cosmos Hub abandon index 0 / 1", () => {
  const w = walletFromMnemonic(ABANDON);
  const d = createCosmosDeriver(w);
  using a0 = d.derive(0);
  using a1 = d.derive(1);
  expect(a0.path).toBe("m/44'/118'/0'/0/0");
  expect(a0.address).toBe("cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4");
  expect(a0.privateKeyHex()).toBe(
    "c4a48e2fce1481cd3294b4490f6678090ea98d3d0e5cd984558ab0968741b104",
  );
  expect(a1.address).toBe("cosmos1jrkmdcwgq94uaamx6zax2luewlhf7u4kucx3kz");
  expect(a1.privateKeyHex()).toBe(
    "c9ba8e1818baf4ceb063420dcedc7a482056a1580e4dbe797af3484aff7b8651",
  );
  w.dispose();
});

test("gold: Osmosis same hash160, different HRP", () => {
  const w = walletFromMnemonic(ABANDON);
  using cosmos = createCosmosDeriver(w, COSMOS_HUB).derive(0);
  using osmo = createCosmosDeriver(w, OSMOSIS).derive(0);
  expect(osmo.address).toBe("osmo19rl4cm2hmr8afy4kldpxz3fka4jguq0a5m7df8");
  const c = bech32.decodeToBytes(cosmos.address);
  const o = bech32.decodeToBytes(osmo.address);
  expect(c.bytes).toEqual(o.bytes);
  w.dispose();
});

test("Terra coin type 330 differs from Hub", () => {
  const w = walletFromMnemonic(ABANDON);
  using cosmos = createCosmosDeriver(w).derive(0);
  using terra = createCosmosDeriver(w, TERRA).derive(0);
  expect(terra.address.startsWith("terra1")).toBe(true);
  expect(terra.path).toBe("m/44'/330'/0'/0/0");
  expect(bech32.decodeToBytes(cosmos.address).bytes).not.toEqual(
    bech32.decodeToBytes(terra.address).bytes,
  );
  w.dispose();
});

test("custom stars config shares coin 118 program", () => {
  const w = walletFromMnemonic(ABANDON);
  const d = createCosmosDeriver(w, cosmosChainConfig("stars", 118));
  expect(d.config.hrp).toBe("stars");
  using stars = d.derive(0);
  using cosmos = createCosmosDeriver(w).derive(0);
  expect(bech32.decodeToBytes(stars.address).bytes).toEqual(
    bech32.decodeToBytes(cosmos.address).bytes,
  );
  w.dispose();
});
