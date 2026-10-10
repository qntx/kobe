import { bech32m } from "@scure/base";
import { expect, test } from "vitest";
import {
  createSparkDeriver,
  encodeSparkAddress,
  SPARK_PURPOSE,
  sparkHrp,
  sparkPath,
  type SparkNetwork,
} from "../../src/chains/spark/index.ts";
import { hexToBytes } from "../../src/crypto/hex.ts";
import { sha256Bytes } from "../../src/crypto/index.ts";
import { walletFromMnemonic } from "../../src/hd/index.ts";

const ABANDON =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

test('gold: SPARK_PURPOSE is SHA-256("spark") last 3 bytes', () => {
  const h = sha256Bytes(new TextEncoder().encode("spark"));
  const u24 = ((h[29] ?? 0) << 16) | ((h[30] ?? 0) << 8) | (h[31] ?? 0);
  expect(u24).toBe(8_797_555);
  expect(SPARK_PURPOSE).toBe(8_797_555);
});

test("gold: encodeSparkAddress matches ethanmarcuss/spark-address", () => {
  const pk = hexToBytes("02894808873b896e21d29856a6d7bb346fb13c019739adb9bf0b6a8b7e28da53da");
  expect(encodeSparkAddress(pk, "mainnet")).toBe(
    "spark1pgss9z2gpzrnhztwy8ffs44x67angma38sqewwddhxlsk65t0c5d5576quly2j",
  );
});

test("gold: Spark mainnet abandon index 0 (kobe-spark)", () => {
  const w = walletFromMnemonic(ABANDON);
  using a = createSparkDeriver(w).derive(0);
  expect(a.path).toBe("m/8797555'/0'/0'");
  expect(sparkPath(0)).toBe("m/8797555'/0'/0'");
  expect(a.address).toBe("spark1pgssy6vty7krpze82ecm8j39gd35v35aqjjmhftc4culawsavkyh564uc6zmqs");
  expect(a.publicKey.kind).toBe("secp256k1-compressed");
  w.dispose();
});

test("testnet and mainnet share keys, not address", () => {
  const w = walletFromMnemonic(ABANDON);
  using main = createSparkDeriver(w, "mainnet").derive(0);
  using testnet = createSparkDeriver(w, "testnet").derive(0);
  expect(main.address.startsWith("spark1")).toBe(true);
  expect(testnet.address.startsWith("sparkt1")).toBe(true);
  expect(main.privateKeyHex()).toBe(testnet.privateKeyHex());
  expect(main.publicKeyHex()).toBe(testnet.publicKeyHex());
  expect(main.address).not.toBe(testnet.address);
  w.dispose();
});

test("every network HRP round-trips", () => {
  const w = walletFromMnemonic(ABANDON);
  const nets: SparkNetwork[] = ["mainnet", "testnet", "signet", "regtest", "local"];
  for (const net of nets) {
    using a = createSparkDeriver(w, net).derive(0);
    const decoded = bech32m.decode(a.address);
    expect(decoded.prefix).toBe(sparkHrp(net));
  }
  w.dispose();
});
