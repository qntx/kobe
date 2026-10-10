import { expect, test } from "vitest";
import { createFilDeriver, filBase32Encode, filPath } from "../../src/chains/fil/index.ts";
import { walletFromMnemonic } from "../../src/hd/index.ts";

const ABANDON =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

test("gold: Filecoin base32 RFC 4648 lowercase no pad", () => {
  expect(filBase32Encode(new Uint8Array())).toBe("");
  expect(filBase32Encode(new TextEncoder().encode("f"))).toBe("my");
  expect(filBase32Encode(new TextEncoder().encode("fo"))).toBe("mzxq");
  expect(filBase32Encode(new TextEncoder().encode("foo"))).toBe("mzxw6");
  expect(filBase32Encode(new TextEncoder().encode("foob"))).toBe("mzxw6yq");
  expect(filBase32Encode(new TextEncoder().encode("fooba"))).toBe("mzxw6ytb");
  expect(filBase32Encode(new TextEncoder().encode("foobar"))).toBe("mzxw6ytboi");
});

test("gold: Filecoin abandon index 0 (kobe-fil)", () => {
  const w = walletFromMnemonic(ABANDON);
  using a = createFilDeriver(w).derive(0);
  expect(a.path).toBe("m/44'/461'/0'/0/0");
  expect(filPath(0)).toBe("m/44'/461'/0'/0/0");
  expect(a.address).toBe("f1qode47ievxlxzk6z2viuovedabmn3tq6t57uqhq");
  expect(a.privateKeyHex()).toBe(
    "e1808079c6734eff9a187c917455dc1b2c70385e13f1cd6cecc94978e57f7f76",
  );
  expect(a.publicKey.kind).toBe("secp256k1-uncompressed");
  w.dispose();
});

test("gold: Filecoin abandon index 1", () => {
  const w = walletFromMnemonic(ABANDON);
  using a = createFilDeriver(w).derive(1);
  expect(a.path).toBe("m/44'/461'/0'/0/1");
  expect(a.address).toBe("f12nzdrhfh6caurft7gwy6d3uazvgy3lhl7rfzvpq");
  expect(a.privateKeyHex()).toBe(
    "ff91cfecbd459ca53112e15c6dd9b26cf4422bb5935c5616d5a6cad95ab0253b",
  );
  w.dispose();
});

test("deriveMany matches scalar derive", () => {
  const w = walletFromMnemonic(ABANDON);
  const d = createFilDeriver(w);
  const batch = d.deriveMany(0, 3);
  for (let i = 0; i < 3; i++) {
    using single = d.derive(i);
    expect(batch[i]!.address).toBe(single.address);
    expect(batch[i]!.path).toBe(single.path);
  }
  for (const a of batch) a.dispose();
  w.dispose();
});

test("passphrase changes address", () => {
  const a = walletFromMnemonic(ABANDON);
  const b = walletFromMnemonic(ABANDON, "TREZOR");
  using aa = createFilDeriver(a).derive(0);
  using bb = createFilDeriver(b).derive(0);
  expect(aa.address).not.toBe(bb.address);
  a.dispose();
  b.dispose();
});
