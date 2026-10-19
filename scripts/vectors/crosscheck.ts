// Second-source audit of the kobe CLI: every account is re-derived with
// Trust Wallet Core (C++/WASM, independent of the reference packages behind
// vectors/) and every path is checked against an independently written
// template table. Wallet Core lacks kaspa, nostr, spark, casper, TON V5R1 and
// the Ledger/Trezor Cardano masters, and ignores the BIP-39 passphrase for
// Cardano; those cases rely on vectors/ alone.
// Run: cargo build -p kobe-cli && bun run crosscheck  (from scripts/vectors)
import { spawnSync } from "node:child_process";
import { initWasm } from "@trustwallet/wallet-core";

const c = await initWasm();
const KOBE = process.env.KOBE_BIN ?? new URL("../../target/debug/kobe", import.meta.url).pathname;
const M12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const M24 = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title";
const SEEDS = [
  { m: M12, p: "" },
  { m: M24, p: "" },
  { m: M12, p: "TREZOR" },
  { m: M24, p: "kobe passphrase 🔑" },
];
const COUNT = 3;

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const concat = (...a: Uint8Array[]) => Uint8Array.from(a.flatMap((x) => [...x]));
let checks = 0;
const failures: string[] = [];
const eq = (what: string, got: unknown, want: unknown) => {
  checks++;
  if (got !== want) failures.push(`${what}\n    kobe: ${got}\n    ref:  ${want}`);
};

function kobe(args: string[], seed: { m: string; p: string }) {
  const r = spawnSync(KOBE, [...args, "-m", "-", "-p", seed.p, "-i", "0", "-c", String(COUNT), "--json", "--reveal"], {
    input: seed.m + "\n",
  });
  const out = JSON.parse(r.stdout.toString());
  if (out.error) throw new Error(`${args.join(" ")}: ${out.error}`);
  return out;
}

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const base32Decode = (s: string) => {
  let bits = 0, acc = 0;
  const out: number[] = [];
  for (const ch of s) {
    acc = (acc << 5) | B32.indexOf(ch);
    bits += 5;
    if (bits >= 8) { bits -= 8; out.push((acc >> bits) & 0xff); }
  }
  return Uint8Array.from(out);
};
// BIP-173 bech32 decode without the 90-char limit (CIP-5 keys exceed it).
const BECH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
function bech32DecodeUnbounded(s: string) {
  const pos = s.lastIndexOf("1");
  const hrp = s.slice(0, pos);
  const values = [...s.slice(pos + 1)].map((ch) => BECH.indexOf(ch));
  const G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of [...[...hrp].map((ch) => ch.charCodeAt(0) >> 5), 0, ...[...hrp].map((ch) => ch.charCodeAt(0) & 31), ...values]) {
    const top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >> i) & 1) chk ^= G[i];
  }
  if (chk !== 1) throw new Error(`bad bech32 checksum: ${s.slice(0, 16)}…`);
  let acc = 0, bits = 0;
  const out: number[] = [];
  for (const v of values.slice(0, -6)) {
    acc = (acc << 5) | v;
    bits += 5;
    if (bits >= 8) { bits -= 8; out.push((acc >> bits) & 0xff); }
  }
  return { hrp, data: Uint8Array.from(out) };
}
const b58 = (s: string) => c.Base58.decodeNoCheck(s);
const b58check = (s: string) => c.Base58.decode(s);

type Ctx = { label: string; seed: { m: string; p: string }; wallet: any; acct: any; i: number; path: string };

function run(
  label: string,
  args: string[],
  coin: any,
  template: (i: number) => string,
  check: (ctx: Ctx, key: any) => void,
) {
  for (const seed of SEEDS) {
    const wallet = c.HDWallet.createWithMnemonic(seed.m, seed.p);
    const out = kobe(args, seed);
    eq(`${label} account count`, out.accounts.length, COUNT);
    out.accounts.forEach((acct: any, i: number) => {
      const path = template(i);
      const ctx = { label: `${label} [${seed.m.split(" ")[0]}/${seed.p || "-"}] ${path}`, seed, wallet, acct, i, path };
      eq(`${ctx.label} path`, acct.path, path);
      check(ctx, wallet.getKey(coin, path));
    });
  }
}

const secpPub = (k: any) => k.getPublicKeySecp256k1(true);
const edPub = (k: any) => k.getPublicKeyEd25519();

function wif(ctx: Ctx, key: any, version: number) {
  const raw = b58check(ctx.acct.private_key);
  eq(`${ctx.label} wif`, hex(raw), hex(concat(Uint8Array.of(version), key.data(), Uint8Array.of(1))));
}

// Bitcoin family
const BTC_KINDS = [["p2pkh", 44], ["p2sh-p2wpkh", 49], ["p2wpkh", 84], ["p2tr", 86]] as const;
const BTC_NETS = [
  { id: "mainnet", coin: 0, pkh: 0x00, sh: 0x05, hrp: "bc", wif: 0x80 },
  { id: "testnet", coin: 1, pkh: 0x6f, sh: 0xc4, hrp: "tb", wif: 0xef },
  { id: "regtest", coin: 1, pkh: 0x6f, sh: 0xc4, hrp: "bcrt", wif: 0xef },
];
function btcAddress(kind: string, pub: any, net: { pkh: number; sh: number; hrp: string }, coin: any, segwitHrp: string) {
  switch (kind) {
    case "p2pkh":
      return c.BitcoinAddress.createWithPublicKey(pub, net.pkh).description();
    case "p2sh-p2wpkh": {
      const script = c.BitcoinScript.buildPayToWitnessPubkeyHash(c.Hash.sha256RIPEMD(pub.data()));
      return c.BitcoinAddress.createWithData(concat(Uint8Array.of(net.sh), c.Hash.sha256RIPEMD(script.data()))).description();
    }
    case "p2wpkh":
      return c.AnyAddress.createBech32WithPublicKey(pub, coin, segwitHrp).description();
    default: {
      const main = c.AnyAddress.createWithPublicKeyDerivation(pub, c.CoinType.bitcoin, c.Derivation.bitcoinTaproot).description();
      return segwitHrp === "bc" ? main : c.Bech32.encodeM(segwitHrp, c.Bech32.decodeM(main));
    }
  }
}
for (const net of BTC_NETS)
  for (const [kind, purpose] of BTC_KINDS)
    for (const [style, tpl] of [
      ["standard", (i: number) => `m/${purpose}'/${net.coin}'/0'/0/${i}`],
      ["account", (i: number) => `m/${purpose}'/${net.coin}'/${i}'/0/0`],
    ] as const)
      run(`bitcoin ${net.id} ${kind} ${style}`, ["bitcoin", "--network", net.id, "--type", kind, "-s", style], c.CoinType.bitcoin, tpl, (ctx, key) => {
        const pub = secpPub(key);
        eq(`${ctx.label} address`, ctx.acct.address, btcAddress(kind, pub, net, c.CoinType.bitcoin, net.hrp));
        eq(`${ctx.label} public_key`, ctx.acct.public_key, hex(pub.data()));
        wif(ctx, key, net.wif);
      });

for (const [kind, purpose] of BTC_KINDS.slice(0, 3))
  for (const [style, tpl] of [
    ["standard", (i: number) => `m/${purpose}'/2'/0'/0/${i}`],
    ["account", (i: number) => `m/${purpose}'/2'/${i}'/0/0`],
  ] as const)
    run(`litecoin ${kind} ${style}`, ["litecoin", "--type", kind, "-s", style], c.CoinType.litecoin, tpl, (ctx, key) => {
      const pub = secpPub(key);
      eq(`${ctx.label} address`, ctx.acct.address, btcAddress(kind, pub, { pkh: 0x30, sh: 0x32, hrp: "ltc" }, c.CoinType.litecoin, "ltc"));
      wif(ctx, key, 0xb0);
    });

for (const [style, tpl] of [
  ["standard", (i: number) => `m/44'/3'/0'/0/${i}`],
  ["account", (i: number) => `m/44'/3'/${i}'/0/0`],
] as const)
  run(`dogecoin ${style}`, ["dogecoin", "-s", style], c.CoinType.dogecoin, tpl, (ctx, key) => {
    eq(`${ctx.label} address`, ctx.acct.address, c.CoinTypeExt.deriveAddress(c.CoinType.dogecoin, key));
    wif(ctx, key, 0x9e);
  });

for (const [style, tpl] of [
  ["standard", (i: number) => `m/44'/145'/0'/0/${i}`],
  ["account", (i: number) => `m/44'/145'/${i}'/0/0`],
] as const)
  run(`bitcoin-cash ${style}`, ["bitcoin-cash", "-s", style], c.CoinType.bitcoinCash, tpl, (ctx, key) => {
    eq(`${ctx.label} address`, ctx.acct.address, c.CoinTypeExt.deriveAddress(c.CoinType.bitcoinCash, key));
    wif(ctx, key, 0x80);
  });

// Account-model secp256k1 chains
const hexKey = (ctx: Ctx, key: any, prefix = "") => eq(`${ctx.label} private_key`, ctx.acct.private_key, prefix + hex(key.data()));
for (const [style, tpl] of [
  ["standard", (i: number) => `m/44'/60'/0'/0/${i}`],
  ["ledger-live", (i: number) => `m/44'/60'/${i}'/0/0`],
  ["ledger-legacy", (i: number) => `m/44'/60'/0'/${i}`],
] as const)
  run(`evm ${style}`, ["evm", "-s", style], c.CoinType.ethereum, tpl, (ctx, key) => {
    eq(`${ctx.label} address`, ctx.acct.address, c.CoinTypeExt.deriveAddress(c.CoinType.ethereum, key));
    eq(`${ctx.label} public_key`, ctx.acct.public_key, hex(key.getPublicKeySecp256k1(false).data()));
    hexKey(ctx, key, "0x");
  });

for (const [style, tpl] of [
  ["standard", (i: number) => `m/44'/195'/0'/0/${i}`],
  ["ledger-live", (i: number) => `m/44'/195'/${i}'/0/0`],
] as const)
  run(`tron ${style}`, ["tron", "-s", style], c.CoinType.tron, tpl, (ctx, key) => {
    eq(`${ctx.label} address`, ctx.acct.address, c.CoinTypeExt.deriveAddress(c.CoinType.tron, key));
    hexKey(ctx, key);
  });

const COSMOS = [
  ["cosmos", 118, c.CoinType.cosmos, null],
  ["osmosis", 118, c.CoinType.osmosis, null],
  ["celestia", 118, c.CoinType.cosmos, "celestia"],
  ["dydx", 118, c.CoinType.dydx, null],
  ["sei", 118, c.CoinType.sei, null],
  ["akash", 118, c.CoinType.akash, null],
  ["terra", 330, c.CoinType.terraV2, null],
  ["secret", 529, c.CoinType.secret, null],
  ["kava", 459, c.CoinType.kava, null],
  ["injective", 60, c.CoinType.nativeInjective, null],
  ["evmos", 60, c.CoinType.nativeEvmos, null],
] as const;
for (const [preset, coinType, coin, hrp] of COSMOS)
  for (const [style, tpl] of [
    ["standard", (i: number) => `m/44'/${coinType}'/0'/0/${i}`],
    ["ledger-live", (i: number) => `m/44'/${coinType}'/${i}'/0/0`],
  ] as const)
    run(`cosmos ${preset} ${style}`, ["cosmos", "--chain", preset, "-s", style], coin, tpl, (ctx, key) => {
      const want = hrp
        ? c.AnyAddress.createBech32WithPublicKey(secpPub(key), coin, hrp).description()
        : c.CoinTypeExt.deriveAddress(coin, key);
      eq(`${ctx.label} address`, ctx.acct.address, want);
      hexKey(ctx, key);
    });
run("cosmos --hrp juno", ["cosmos", "--hrp", "juno"], c.CoinType.cosmos, (i) => `m/44'/118'/0'/0/${i}`, (ctx, key) => {
  eq(`${ctx.label} address`, ctx.acct.address, c.AnyAddress.createBech32WithPublicKey(secpPub(key), c.CoinType.cosmos, "juno").description());
});

for (const [style, tpl] of [
  ["standard", (i: number) => `m/44'/144'/0'/0/${i}`],
  ["ledger-live", (i: number) => `m/44'/144'/${i}'/0/0`],
] as const)
  run(`xrpl ${style}`, ["xrpl", "-s", style], c.CoinType.xrp, tpl, (ctx, key) => {
    eq(`${ctx.label} address`, ctx.acct.address, c.CoinTypeExt.deriveAddress(c.CoinType.xrp, key));
    eq(`${ctx.label} public_key`, ctx.acct.public_key, hex(secpPub(key).data()));
    hexKey(ctx, key);
  });

for (const net of ["mainnet", "testnet"])
  run(`filecoin ${net}`, ["filecoin", "--network", net], c.CoinType.filecoin, (i) => `m/44'/461'/0'/0/${i}`, (ctx, key) => {
    const main = c.CoinTypeExt.deriveAddress(c.CoinType.filecoin, key);
    eq(`${ctx.label} address`, ctx.acct.address, net === "mainnet" ? main : "t" + main.slice(1));
    const lotus = JSON.parse(Buffer.from(ctx.acct.private_key, "hex").toString());
    eq(`${ctx.label} lotus type`, lotus.Type, "secp256k1");
    eq(`${ctx.label} lotus key`, Buffer.from(lotus.PrivateKey, "base64").toString("hex"), hex(key.data()));
  });

// SLIP-10 ed25519 chains
function keypair58(ctx: Ctx, key: any, encoded: string) {
  const raw = b58(encoded);
  eq(`${ctx.label} keypair`, hex(raw), hex(key.data()) + hex(edPub(key).data()));
}
for (const [style, tpl] of [
  ["bip44-change", (i: number) => `m/44'/501'/${i}'/0'`],
  ["bip44", (i: number) => `m/44'/501'/${i}'`],
] as const)
  run(`solana ${style}`, ["solana", "-s", style], c.CoinType.solana, tpl, (ctx, key) => {
    eq(`${ctx.label} address`, ctx.acct.address, c.CoinTypeExt.deriveAddress(c.CoinType.solana, key));
    keypair58(ctx, key, ctx.acct.private_key);
  });

{
  for (const seed of SEEDS) {
    const wallet = c.HDWallet.createWithMnemonic(seed.m, seed.p);
    const out = kobe(["solana", "-s", "root"], seed);
    eq("solana root count", out.accounts.length, 1);
    const key = wallet.getKey(c.CoinType.solana, "m/44'/501'");
    eq("solana root path", out.accounts[0].path, "m/44'/501'");
    eq("solana root address", out.accounts[0].address, c.CoinTypeExt.deriveAddress(c.CoinType.solana, key));
  }
}

run("sui", ["sui"], c.CoinType.sui, (i) => `m/44'/784'/${i}'/0'/0'`, (ctx, key) => {
  eq(`${ctx.label} address`, ctx.acct.address, c.CoinTypeExt.deriveAddress(c.CoinType.sui, key));
  eq(`${ctx.label} public_key`, ctx.acct.public_key, hex(edPub(key).data()));
  const words = c.Bech32.decode(ctx.acct.private_key);
  eq(`${ctx.label} suiprivkey`, hex(words), "00" + hex(key.data()));
});

run("aptos", ["aptos"], c.CoinType.aptos, (i) => `m/44'/637'/${i}'/0'/0'`, (ctx, key) => {
  eq(`${ctx.label} address`, ctx.acct.address, c.CoinTypeExt.deriveAddress(c.CoinType.aptos, key));
  hexKey(ctx, key, "ed25519-priv-0x");
});

for (const [style, tpl] of [
  ["standard", (i: number) => `m/44'/607'/${i}'`],
  ["ledger-live", (i: number) => `m/44'/607'/0'/0'/${i}'/0'`],
] as const)
  for (const testnet of [false, true])
    for (const bounceable of [false, true]) {
      const flags = ["ton", "-s", style, ...(testnet ? ["--testnet"] : []), ...(bounceable ? ["--bounceable"] : [])];
      run(`ton v4r2 ${style} testnet=${testnet} bounceable=${bounceable}`, flags, c.CoinType.ton, tpl, (ctx, key) => {
        const raw = c.CoinTypeExt.deriveAddress(c.CoinType.ton, key);
        eq(`${ctx.label} address`, ctx.acct.address, c.TONAddressConverter.toUserFriendly(raw, bounceable, testnet));
        hexKey(ctx, key);
      });
    }

run("stellar", ["stellar"], c.CoinType.stellar, (i) => `m/44'/148'/${i}'`, (ctx, key) => {
  eq(`${ctx.label} address`, ctx.acct.address, c.CoinTypeExt.deriveAddress(c.CoinType.stellar, key));
  const raw = base32Decode(ctx.acct.private_key);
  eq(`${ctx.label} strkey version`, raw[0], 18 << 3);
  eq(`${ctx.label} strkey seed`, hex(raw.slice(1, 33)), hex(key.data()));
});

for (const [style, tpl] of [
  ["standard", (i: number) => `m/44'/397'/${i}'`],
  ["ledger-live", (i: number) => `m/44'/397'/0'/0'/${i}'`],
] as const)
  run(`near ${style}`, ["near", "-s", style], c.CoinType.near, tpl, (ctx, key) => {
    eq(`${ctx.label} address`, ctx.acct.address, c.CoinTypeExt.deriveAddress(c.CoinType.near, key));
    eq(`${ctx.label} public_key`, ctx.acct.public_key, "ed25519:" + c.Base58.encodeNoCheck(edPub(key).data()));
    keypair58(ctx, key, ctx.acct.private_key.replace(/^ed25519:/, ""));
  });

// Cardano (wallet-core implements the Icarus master)
SEEDS.splice(0, SEEDS.length, ...SEEDS.filter((s) => s.p === ""));
run("cardano icarus", ["cardano", "--master", "icarus"], c.CoinType.cardano, (i) => `m/1852'/1815'/${i}'/0/0`, (ctx, key) => {
  const base = c.CoinTypeExt.deriveAddress(c.CoinType.cardano, key);
  eq(`${ctx.label} address`, ctx.acct.address, base);
  eq(`${ctx.label} stake_address`, ctx.acct.stake_address, c.Cardano.getStakingAddress(base));
  const { hrp, data } = bech32DecodeUnbounded(ctx.acct.private_key);
  eq(`${ctx.label} addr_xsk hrp`, hrp, "addr_xsk");
  eq(`${ctx.label} addr_xsk`, hex(data), hex(key.data().slice(0, 96)));
});

console.log(`${checks} checks, ${failures.length} failures`);
for (const f of failures.slice(0, 40)) console.log("FAIL " + f);
process.exit(failures.length ? 1 : 0);
