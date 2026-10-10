import { base64urlnopad } from "@scure/base";
import { expect, test } from "vitest";
import {
  createTonAddressFormat,
  createTonDeriver,
  crc16Ccitt,
  parseTonStyle,
  TON_ADDRESS_BOUNCEABLE,
  TON_ADDRESS_DEFAULT,
  TON_ADDRESS_TESTNET,
  tonPath,
  tonWalletId,
} from "../../src/chains/ton/index.ts";
import { DeriveError } from "../../src/errors/derive.ts";
import { walletFromMnemonic } from "../../src/hd/index.ts";

const ABANDON =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

test("gold: TON v5r1 mainnet abandon index 0 (kobe-ton)", () => {
  const w = walletFromMnemonic(ABANDON);
  using a = createTonDeriver(w).derive(0);
  expect(a.path).toBe("m/44'/607'/0'");
  expect(tonPath("standard", 0)).toBe("m/44'/607'/0'");
  expect(a.privateKeyHex()).toBe(
    "b477ef5ed17fb8a2b8faddd7a9835a227243a82c70b190c7af4896155aa7df9f",
  );
  expect(a.publicKeyHex()).toBe("7952e94118f34607c75e23258dd9220d66ccac5a3ee074125c25068e8107bfbf");
  expect(a.address).toBe("UQBHyu-oZVDHRYQ1-rKlGqpHy5yAqanPBirEQNMNOmfHLtaT");
  w.dispose();
});

test("gold: TON v5r1 bounceable shares account hash", () => {
  const w = walletFromMnemonic(ABANDON);
  using bounce = createTonDeriver(w, TON_ADDRESS_BOUNCEABLE).derive(0);
  using plain = createTonDeriver(w, TON_ADDRESS_DEFAULT).derive(0);
  expect(bounce.address).toBe("EQBHyu-oZVDHRYQ1-rKlGqpHy5yAqanPBirEQNMNOmfHLotW");
  const mainnet = base64urlnopad.decode(plain.address);
  const bounceable = base64urlnopad.decode(bounce.address);
  expect(mainnet.subarray(1, 34)).toEqual(bounceable.subarray(1, 34));
  expect(mainnet[0]).not.toBe(bounceable[0]);
  w.dispose();
});

test("testnet non-bounceable prefix 0Q", () => {
  const w = walletFromMnemonic(ABANDON);
  using a = createTonDeriver(w, TON_ADDRESS_TESTNET).derive(0);
  expect(a.address.startsWith("0Q")).toBe(true);
  w.dispose();
});

test("masterchain workchain -1 encodes 0xFF", () => {
  const w = walletFromMnemonic(ABANDON);
  using a = createTonDeriver(w, createTonAddressFormat(-1, false, false)).derive(0);
  const decoded = base64urlnopad.decode(a.address);
  expect(decoded.length).toBe(36);
  expect(decoded[0]).toBe(0x51);
  expect(decoded[1]).toBe(0xff);
  const crc = crc16Ccitt(decoded.subarray(0, 34));
  expect(decoded[34]).toBe((crc >>> 8) & 0xff);
  expect(decoded[35]).toBe(crc & 0xff);
  w.dispose();
});

test("gold: walletId matches @ton/core WalletV5R1WalletId", () => {
  const cases: Array<[boolean, number, number]> = [
    [false, 0, 2_147_483_409],
    [false, -1, 8_388_369],
    [true, 0, 2_147_483_645],
    [true, -1, 8_388_605],
  ];
  for (const [testnet, workchain, expected] of cases) {
    expect(tonWalletId(createTonAddressFormat(workchain, false, testnet))).toBe(expected);
  }
});

test("gold: CRC-16/XMODEM 123456789", () => {
  expect(crc16Ccitt(new TextEncoder().encode("123456789"))).toBe(0x31c3);
});

test("deriveManyWith matches scalar for both styles", () => {
  const w = walletFromMnemonic(ABANDON);
  const d = createTonDeriver(w);
  for (const style of ["standard", "ledger-live"] as const) {
    const batch = d.deriveManyWith(style, 0, 3);
    for (let i = 0; i < 3; i++) {
      using single = d.deriveWith(style, i);
      expect(batch[i]!.path).toBe(single.path);
      expect(batch[i]!.address).toBe(single.address);
    }
    for (const a of batch) a.dispose();
  }
  w.dispose();
});

test("parseTonStyle aliases; unknown throws", () => {
  expect(parseTonStyle("Tonkeeper")).toBe("standard");
  expect(parseTonStyle("live")).toBe("ledger-live");
  expect(() => parseTonStyle("bip44")).toThrow(DeriveError);
});
