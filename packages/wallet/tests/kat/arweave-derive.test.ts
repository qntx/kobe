import { expect, test } from "vitest";
import {
  arweaveAddressFromCompressed,
  arweaveBase64Url,
  arweaveOwnerFromCompressed,
  arweavePath,
  createArweaveDeriver,
} from "../../src/chains/arweave/index.ts";
import { hexToBytes } from "../../src/crypto/hex.ts";
import { sha256Bytes } from "../../src/crypto/index.ts";
import { walletFromMnemonic } from "../../src/hd/index.ts";

const ABANDON =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const SK0 = "130721c87ce0ace0999c94a5943d055b224411eda752680ca24969d0837ff152";
const ADDR0 = "G3y00z9F3EvSzJprpIH6vPqHVZPH0rLqLrg0JOsd88Y";
const OWNER0 = "A9-agndOu82Va7G9inhR8lqV3LEbBkp0zK3PJ3zLbTtv";
const PK0 = "03df9a82774ebbcd956bb1bd8a7851f25a95dcb11b064a74ccadcf277ccb6d3b6f";

test("gold: Arweave abandon index 0 (kobe-arweave)", () => {
  const w = walletFromMnemonic(ABANDON);
  using a = createArweaveDeriver(w).derive(0);
  expect(a.path).toBe("m/44'/472'/0'/0/0");
  expect(arweavePath(0)).toBe("m/44'/472'/0'/0/0");
  expect(a.address).toBe(ADDR0);
  expect(a.address.length).toBe(43);
  expect(a.privateKeyHex()).toBe(SK0);
  expect(a.publicKeyHex()).toBe(PK0);
  expect(a.publicKey.kind).toBe("secp256k1-compressed");
  w.dispose();
});

test("gold: Arweave abandon index 1", () => {
  const w = walletFromMnemonic(ABANDON);
  using a = createArweaveDeriver(w).derive(1);
  expect(a.path).toBe("m/44'/472'/0'/0/1");
  expect(a.address).toBe("s67JULQPjY6wpxYV4imfx_Ui6twtC_jfxnluJT4GOSo");
  expect(a.privateKeyHex()).toBe(
    "a8822ffcffba36d726f8ddd866963325b668c36d780f73fcf245a59babd8aa12",
  );
  w.dispose();
});

test("gold: address and owner from compressed pubkey", () => {
  const pk = hexToBytes(PK0);
  expect(arweaveAddressFromCompressed(pk)).toBe(ADDR0);
  expect(arweaveOwnerFromCompressed(pk)).toBe(OWNER0);
});

test("uncompressed SHA-256 is not the protocol address", () => {
  const w = walletFromMnemonic(ABANDON);
  using a = createArweaveDeriver(w).derive(0);
  const key = w.deriveSecp256k1(a.path);
  const uncompressed = key.uncompressedPublicKey();
  key.dispose();
  const wrong = arweaveBase64Url(sha256Bytes(uncompressed));
  expect(wrong).toBe("eOqGD0loQiFvP7w-aQNq1DoVyTJM_eUnPG78vKY3JIM");
  expect(a.address).not.toBe(wrong);
  w.dispose();
});

test("deriveMany matches scalar derive", () => {
  const w = walletFromMnemonic(ABANDON);
  const d = createArweaveDeriver(w);
  const batch = d.deriveMany(0, 3);
  for (let i = 0; i < 3; i++) {
    using single = d.derive(i);
    expect(batch[i]!.address).toBe(single.address);
    expect(batch[i]!.path).toBe(single.path);
  }
  for (const a of batch) a.dispose();
  w.dispose();
});

test("passphrase changes address; deriveAt honours account segment", () => {
  const a = walletFromMnemonic(ABANDON);
  const b = walletFromMnemonic(ABANDON, "TREZOR");
  using aa = createArweaveDeriver(a).derive(0);
  using bb = createArweaveDeriver(b).derive(0);
  expect(aa.address).not.toBe(bb.address);
  using alt = createArweaveDeriver(a).deriveAt("m/44'/472'/1'/0/0");
  expect(alt.path).toBe("m/44'/472'/1'/0/0");
  expect(alt.address).not.toBe(aa.address);
  a.dispose();
  b.dispose();
});
