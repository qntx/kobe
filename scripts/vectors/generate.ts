// Generate vectors/*.json from independent reference implementations.
// Run: bun run generate  (from scripts/vectors)
import { writeFileSync } from "node:fs";
import { HDKey } from "@scure/bip32";
import { mnemonicToSeedSync } from "@scure/bip39";
import * as btc from "@scure/btc-signer";
import { bech32 } from "@scure/base";
import { HDKey as Slip10 } from "micro-key-producer/slip10.js";
import { Keypair } from "@solana/web3.js";
import { mnemonicToAccount } from "viem/accounts";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ripemd160 } from "@noble/hashes/legacy.js";
import bs58 from "bs58";
import { TronWeb } from "tronweb";
import { Wallet as XrplWallet } from "xrpl";
import { encodeAccountID } from "ripple-address-codec";
import { DirectSecp256k1HdWallet } from "@cosmjs/proto-signing";
import { stringToPath } from "@cosmjs/crypto";
import { newSecp256k1Address } from "@glif/filecoin-address";
import { encodeCashAddress, hash160 } from "@bitauth/libauth";
import { privateKeyFromSeedWords } from "nostr-tools/nip06";
import * as nip19 from "nostr-tools/nip19";
import { getPublicKey as nostrGetPublicKey } from "nostr-tools";
import { encodeSparkAddress } from "@buildonspark/spark-sdk";
import { PublicKey as CasperPublicKey } from "casper-js-sdk";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { Account as AptosAccount, Ed25519PrivateKey } from "@aptos-labs/ts-sdk";
import { WalletContractV4, WalletContractV5R1 } from "@ton/ton";
import { StrKey } from "@stellar/stellar-sdk";
import { parseSeedPhrase } from "near-seed-phrase";
import * as CSL from "@emurgo/cardano-serialization-lib-nodejs";
import { mnemonicToEntropy } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";
import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { concatBytes } from "@noble/hashes/utils.js";
import { readFileSync } from "node:fs";

const M12 =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const M24 =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

const SEEDS = [
  { mnemonic: M12, passphrase: "" },
  { mnemonic: M24, passphrase: "" },
  { mnemonic: M12, passphrase: "TREZOR" },
];

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const unhex = (s: string) => new Uint8Array(Buffer.from(s, "hex"));
const INDICES = [0, 1, 2];

type Case = Record<string, unknown>;
interface VecFile {
  schema: 1;
  source: { kind: "reference"; name: string; version: string };
  cases: Case[];
}
const file = (name: string, version: string, cases: Case[]): VecFile => ({
  schema: 1,
  source: { kind: "reference", name, version },
  cases,
});
const emit = (n: string, f: VecFile) =>
  writeFileSync(`../../vectors/${n}.json`, JSON.stringify(f, null, 2) + "\n");

const counts: [string, number][] = [];
const emitCounted = (n: string, f: VecFile) => {
  emit(n, f);
  counts.push([n, f.cases.length]);
};

const seedOf = (s: { mnemonic: string; passphrase: string }) =>
  mnemonicToSeedSync(s.mnemonic, s.passphrase);
const bip32Root = (s: { mnemonic: string; passphrase: string }) =>
  HDKey.fromMasterSeed(seedOf(s));
const slip10Root = (s: { mnemonic: string; passphrase: string }) =>
  Slip10.fromMasterSeed(seedOf(s));

// btc
const BTC_NETWORKS: { id: string; coin: number; net: typeof btc.NETWORK }[] = [
  { id: "mainnet", coin: 0, net: btc.NETWORK },
  { id: "testnet", coin: 1, net: btc.TEST_NETWORK },
  { id: "regtest", coin: 1, net: { ...btc.TEST_NETWORK, bech32: "bcrt" } },
];
const BTC_KINDS = [
  { id: "p2pkh", purpose: 44 },
  { id: "p2sh-p2wpkh", purpose: 49 },
  { id: "p2wpkh", purpose: 84 },
  { id: "p2tr", purpose: 86 },
];
const accountStyles = (purpose: (k: { id: string }) => number, coin: number) => [
  { id: "standard", tpl: (p: number) => `m/${p}'/${coin}'/0'/0/{i}` },
  { id: "account", tpl: (p: number) => `m/${p}'/${coin}'/{i}'/0/0` },
];
const btcAddress = (kind: string, pub: Uint8Array, net: typeof btc.NETWORK) => {
  switch (kind) {
    case "p2pkh":
      return btc.p2pkh(pub, net).address;
    case "p2sh-p2wpkh":
      return btc.p2sh(btc.p2wpkh(pub, net), net).address;
    case "p2wpkh":
      return btc.p2wpkh(pub, net).address;
    default:
      return btc.p2tr(pub.slice(1), undefined, net).address;
  }
};

const btcCases: Case[] = [];
for (const s of SEEDS) {
  const root = bip32Root(s);
  for (const network of BTC_NETWORKS)
    for (const kind of BTC_KINDS)
      for (const style of accountStyles(() => kind.purpose, network.coin))
        for (const index of INDICES) {
          const path = style.tpl(kind.purpose).replace("{i}", String(index));
          const node = root.derive(path);
          if (!node.privateKey || !node.publicKey) throw new Error("no key");
          btcCases.push({
            mnemonic: s.mnemonic,
            passphrase: s.passphrase,
            options: { network: network.id, kind: kind.id },
            style: style.id,
            index,
            path,
            address: btcAddress(kind.id, node.publicKey, network.net),
            public_key: hex(node.publicKey),
            private_key: btc.WIF(network.net).encode(node.privateKey),
          });
        }
}
emitCounted(
  "bitcoin",
  file(
    "bitcoin",
    "@scure/bip32 2.4.0 + @scure/btc-signer 2.4.1 (seeds: @scure/bip39 2.4.0)",
    btcCases
  )
);

// ltc / doge — @scure/btc-signer with chain params
const LTC = { bech32: "ltc", pubKeyHash: 0x30, scriptHash: 0x32, wif: 0xb0 };
const DOGE = { bech32: "doge", pubKeyHash: 0x1e, scriptHash: 0x16, wif: 0x9e };

const ltcCases: Case[] = [];
const LTC_KINDS = [
  { id: "p2pkh", purpose: 44 },
  { id: "p2sh-p2wpkh", purpose: 49 },
  { id: "p2wpkh", purpose: 84 },
];
for (const s of SEEDS) {
  const root = bip32Root(s);
  for (const kind of LTC_KINDS)
    for (const style of accountStyles(() => kind.purpose, 2))
      for (const index of INDICES) {
        const path = style.tpl(kind.purpose).replace("{i}", String(index));
        const node = root.derive(path);
        if (!node.privateKey || !node.publicKey) throw new Error("no key");
        ltcCases.push({
          mnemonic: s.mnemonic,
          passphrase: s.passphrase,
          options: { kind: kind.id },
          style: style.id,
          index,
          path,
          address: btcAddress(kind.id, node.publicKey, LTC as typeof btc.NETWORK),
          public_key: hex(node.publicKey),
          private_key: btc.WIF(LTC as typeof btc.NETWORK).encode(node.privateKey),
        });
      }
}
emitCounted(
  "litecoin",
  file("litecoin", "@scure/bip32 2.4.0 + @scure/btc-signer 2.4.1 (LTC params)", ltcCases)
);

const dogeCases: Case[] = [];
for (const s of SEEDS) {
  const root = bip32Root(s);
  for (const style of accountStyles(() => 44, 3))
    for (const index of INDICES) {
      const path = style.tpl(44).replace("{i}", String(index));
      const node = root.derive(path);
      if (!node.privateKey || !node.publicKey) throw new Error("no key");
      dogeCases.push({
        mnemonic: s.mnemonic,
        passphrase: s.passphrase,
        style: style.id,
        index,
        path,
        address: btc.p2pkh(node.publicKey, DOGE as typeof btc.NETWORK).address,
        public_key: hex(node.publicKey),
        private_key: btc.WIF(DOGE as typeof btc.NETWORK).encode(node.privateKey),
      });
    }
}
emitCounted(
  "dogecoin",
  file("dogecoin", "@scure/bip32 2.4.0 + @scure/btc-signer 2.4.1 (DOGE params)", dogeCases)
);

// bch — @bitauth/libauth cashaddr
const bchCases: Case[] = [];
for (const s of SEEDS) {
  const root = bip32Root(s);
  for (const style of accountStyles(() => 44, 145))
    for (const index of INDICES) {
      const path = style.tpl(44).replace("{i}", String(index));
      const node = root.derive(path);
      if (!node.privateKey || !node.publicKey) throw new Error("no key");
      const res = encodeCashAddress({
        prefix: "bitcoincash",
        type: "p2pkh",
        payload: hash160(node.publicKey),
      });
      const address = typeof res === "string" ? res : (res as { address: string }).address;
      bchCases.push({
        mnemonic: s.mnemonic,
        passphrase: s.passphrase,
        style: style.id,
        index,
        path,
        address,
        public_key: hex(node.publicKey),
        private_key: btc.WIF(btc.NETWORK).encode(node.privateKey),
      });
    }
}
emitCounted("bitcoin-cash", file("bitcoin-cash", "@scure/bip32 2.4.0 + @bitauth/libauth 3.0.0 cashaddr", bchCases));

// evm — viem
const EVM_STYLES = [
  { id: "standard", tpl: (i: number) => `m/44'/60'/0'/0/${i}` },
  { id: "ledger-live", tpl: (i: number) => `m/44'/60'/${i}'/0/0` },
  { id: "ledger-legacy", tpl: (i: number) => `m/44'/60'/0'/${i}` },
];
const evmCases: Case[] = [];
for (const s of SEEDS)
  for (const style of EVM_STYLES)
    for (const index of INDICES) {
      const path = style.tpl(index);
      const account = mnemonicToAccount(s.mnemonic, { path, passphrase: s.passphrase });
      const hk = account.getHdKey();
      if (!hk.privateKey || !hk.publicKey) throw new Error("no key");
      const uncompressed = secp256k1.Point.fromBytes(hk.publicKey).toBytes(false);
      evmCases.push({
        mnemonic: s.mnemonic,
        passphrase: s.passphrase,
        style: style.id,
        index,
        path,
        address: account.address,
        public_key: hex(uncompressed),
        private_key: "0x" + hex(hk.privateKey),
      });
    }
emitCounted("evm", file("evm", "viem 2.57.4 mnemonicToAccount/HDKey", evmCases));

// tron — tronweb (normalize: strip 0x prefixes)
const TRON_STYLES = [
  { id: "standard", tpl: (i: number) => `m/44'/195'/0'/0/${i}` },
  { id: "ledger-live", tpl: (i: number) => `m/44'/195'/${i}'/0/0` },
];
const tronCases: Case[] = [];
for (const s of SEEDS)
  for (const style of TRON_STYLES)
    for (const index of INDICES) {
      const path = style.tpl(index);
      const acc = TronWeb.fromMnemonic(s.mnemonic, path, s.passphrase);
      tronCases.push({
        mnemonic: s.mnemonic,
        passphrase: s.passphrase,
        style: style.id,
        index,
        path,
        address: acc.address,
        public_key: acc.publicKey.replace(/^0x/, ""),
        private_key: acc.privateKey.replace(/^0x/, ""),
      });
    }
emitCounted("tron", file("tron", "tronweb 6.5.1 fromMnemonic (0x prefixes stripped)", tronCases));

// cosmos — @cosmjs/proto-signing for secp presets; viem + @scure/base bech32 for eth presets
const COSMOS_PRESETS = [
  { id: "cosmos", coin: 118, hrp: "cosmos", eth: false },
  { id: "osmosis", coin: 118, hrp: "osmo", eth: false },
  { id: "celestia", coin: 118, hrp: "celestia", eth: false },
  { id: "dydx", coin: 118, hrp: "dydx", eth: false },
  { id: "sei", coin: 118, hrp: "sei", eth: false },
  { id: "akash", coin: 118, hrp: "akash", eth: false },
  { id: "terra", coin: 330, hrp: "terra", eth: false },
  { id: "secret", coin: 529, hrp: "secret", eth: false },
  { id: "kava", coin: 459, hrp: "kava", eth: false },
  { id: "injective", coin: 60, hrp: "inj", eth: true },
  { id: "evmos", coin: 60, hrp: "evmos", eth: true },
];
const COSMOS_STYLES = [
  { id: "standard", tpl: (c: number, i: number) => `m/44'/${c}'/0'/0/${i}` },
  { id: "ledger-live", tpl: (c: number, i: number) => `m/44'/${c}'/${i}'/0/0` },
];
const cosmosCases: Case[] = [];
for (const s of SEEDS)
  for (const preset of COSMOS_PRESETS)
    for (const style of COSMOS_STYLES)
      for (const index of INDICES) {
        const path = style.tpl(preset.coin, index);
        const entry: Case = {
          mnemonic: s.mnemonic,
          passphrase: s.passphrase,
          options: { chain: preset.id },
          style: style.id,
          index,
          path,
        };
        if (preset.eth) {
          const account = mnemonicToAccount(s.mnemonic, {
            path,
            passphrase: s.passphrase,
          });
          const hk = account.getHdKey();
          if (!hk.privateKey || !hk.publicKey) throw new Error("no key");
          const uncompressed = secp256k1.Point.fromBytes(hk.publicKey).toBytes(false);
          entry.address = bech32.encode(
            preset.hrp,
            bech32.toWords(unhex(account.address.slice(2)))
          );
          entry.public_key = hex(uncompressed);
          entry.private_key = hex(hk.privateKey);
        } else {
          const w = await DirectSecp256k1HdWallet.fromMnemonic(s.mnemonic, {
            prefix: preset.hrp,
            hdPaths: [stringToPath(path)],
            bip39Password: s.passphrase || undefined,
          });
          const [acc] = await w.getAccounts();
          const node = bip32Root(s).derive(path);
          if (!node.privateKey) throw new Error("no key");
          entry.address = acc.address;
          entry.public_key = hex(acc.pubkey);
          entry.private_key = hex(node.privateKey);
        }
        cosmosCases.push(entry);
      }
// --hrp override cases: cosmos preset payload re-encoded under a custom hrp.
for (const index of INDICES) {
  const path = `m/44'/118'/0'/0/${index}`;
  const w = await DirectSecp256k1HdWallet.fromMnemonic(M12, {
    prefix: "osmo",
    hdPaths: [stringToPath(path)],
  });
  const [acc] = await w.getAccounts();
  const node = HDKey.fromMasterSeed(mnemonicToSeedSync(M12, "")).derive(path);
  cosmosCases.push({
    mnemonic: M12,
    passphrase: "",
    options: { chain: "cosmos", hrp: "osmo" },
    style: "standard",
    index,
    path,
    address: acc.address,
    public_key: hex(acc.pubkey),
    private_key: hex(node.privateKey!),
  });
}
emitCounted(
  "cosmos",
  file(
    "cosmos",
    "@cosmjs/proto-signing 0.39.0 + @cosmjs/crypto 0.39.0 (secp presets); viem 2.57.4 + @scure/base 2.4.0 (eth presets)",
    cosmosCases
  )
);

// xrp — xrpl Wallet.fromMnemonic (normalize: lowercase, strip 00 private-key prefix)
const XRP_STYLES = [
  { id: "standard", tpl: (i: number) => `m/44'/144'/0'/0/${i}` },
  { id: "ledger-live", tpl: (i: number) => `m/44'/144'/${i}'/0/0` },
];
const xrpCases: Case[] = [];
for (const s of SEEDS)
  for (const style of XRP_STYLES)
    for (const index of INDICES) {
      const path = style.tpl(index);
      if (s.passphrase === "") {
        const w = XrplWallet.fromMnemonic(s.mnemonic, { derivationPath: path });
        xrpCases.push({
          mnemonic: s.mnemonic,
          passphrase: s.passphrase,
          style: style.id,
          index,
          path,
          address: w.classicAddress,
          public_key: w.publicKey.toLowerCase(),
          private_key: w.privateKey.toLowerCase().replace(/^00/, ""),
        });
      } else {
        // xrpl.js has no bip39-passphrase support: keys via @scure/bip32,
        // address via xrpl's own ripple-address-codec.
        const node = bip32Root(s).derive(path);
        if (!node.privateKey || !node.publicKey) throw new Error("no key");
        xrpCases.push({
          mnemonic: s.mnemonic,
          passphrase: s.passphrase,
          style: style.id,
          index,
          path,
          address: encodeAccountID(ripemd160(sha256(node.publicKey))),
          public_key: hex(node.publicKey),
          private_key: hex(node.privateKey),
        });
      }
    }
emitCounted(
  "xrpl",
  file(
    "xrpl",
    "xrpl 5.3.0 Wallet.fromMnemonic (hex normalized to lowercase, 00 seed prefix stripped); passphrase cases: @scure/bip32 2.4.0 + ripple-address-codec",
    xrpCases
  )
);

// fil — @scure/bip32 keys + @glif/filecoin-address; private key = Lotus export JSON as hex
const FIL_NETWORKS = [
  { id: "mainnet", prefix: "f" as const },
  { id: "testnet", prefix: "t" as const },
];
const filCases: Case[] = [];
for (const s of SEEDS) {
  const root = bip32Root(s);
  for (const net of FIL_NETWORKS)
    for (const index of INDICES) {
      const path = `m/44'/461'/0'/0/${index}`;
      const node = root.derive(path);
      if (!node.privateKey || !node.publicKey) throw new Error("no key");
      const uncompressed = secp256k1.Point.fromBytes(node.publicKey).toBytes(false);
      const lotus = JSON.stringify({
        Type: "secp256k1",
        PrivateKey: Buffer.from(node.privateKey).toString("base64"),
      });
      filCases.push({
        mnemonic: s.mnemonic,
        passphrase: s.passphrase,
        options: { network: net.id },
        style: "standard",
        index,
        path,
        address: newSecp256k1Address(uncompressed, net.prefix).toString(),
        public_key: hex(uncompressed),
        private_key: Buffer.from(lotus, "utf8").toString("hex"),
      });
    }
}
emitCounted(
  "filecoin",
  file("filecoin", "@scure/bip32 2.4.0 + @glif/filecoin-address 4.0.0", filCases)
);

// kaspa — @scure/bip32 key material; address encoding implemented here per the
// kaspa spec (verified against the official rusty-kaspa vectors in
// vectors/kaspa-address.json).
const KASPA_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const KASPA_GENERATORS = [
  0x98f2bc8e61n,
  0x79b76d99e2n,
  0xf33e5fb3c4n,
  0xae2eabe2a8n,
  0x1e4f43e470n,
];
const kaspaPolymod = (values: number[]): bigint => {
  let c = 1n;
  for (const d of values) {
    const c0 = c >> 35n;
    c = ((c & 0x07ffffffffn) << 5n) | BigInt(d);
    KASPA_GENERATORS.forEach((g, i) => {
      if (((c0 >> BigInt(i)) & 1n) !== 0n) c ^= g;
    });
  }
  return c ^ 1n;
};
const conv8to5 = (data: Uint8Array): number[] => {
  const out: number[] = [];
  let acc = 0,
    bits = 0;
  for (const b of data) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out.push((acc >> bits) & 0x1f);
    }
  }
  if (bits > 0) out.push((acc << (5 - bits)) & 0x1f);
  return out;
};
const kaspaAddress = (prefix: string, version: number, payload: Uint8Array): string => {
  const fivebit = conv8to5(new Uint8Array([version, ...payload]));
  const checksum = kaspaPolymod([
    ...prefix.split("").map((c) => c.charCodeAt(0) & 0x1f),
    0,
    ...fivebit,
    0, 0, 0, 0, 0, 0, 0, 0,
  ]);
  const chk: number[] = [];
  for (let i = 7; i >= 0; i--) chk.push(Number((checksum >> BigInt(i * 5)) & 0x1fn));
  return prefix + ":" + [...fivebit, ...chk].map((v) => KASPA_CHARSET[v]).join("");
};
const kaspaCases: Case[] = [];
for (const s of SEEDS) {
  const root = bip32Root(s);
  for (const net of [
    { id: "mainnet", prefix: "kaspa" },
    { id: "testnet", prefix: "kaspatest" },
  ])
    for (const index of INDICES) {
      const path = `m/44'/111111'/0'/0/${index}`;
      const node = root.derive(path);
      if (!node.privateKey || !node.publicKey) throw new Error("no key");
      const xOnly = node.publicKey.slice(1);
      kaspaCases.push({
        mnemonic: s.mnemonic,
        passphrase: s.passphrase,
        options: { network: net.id },
        style: "standard",
        index,
        path,
        address: kaspaAddress(net.prefix, 0, xOnly),
        public_key: hex(xOnly),
        private_key: hex(node.privateKey),
      });
    }
}
// `onekey` encoding: the BIP-341 key-path tweak of the x-only key
// (@scure/btc-signer p2tr.tweakedPubkey), exported key stays raw.
for (const s of SEEDS) {
  const root = bip32Root(s);
  for (const net of [
    { id: "mainnet", prefix: "kaspa" },
    { id: "testnet", prefix: "kaspatest" },
  ])
    for (const index of INDICES) {
      const path = `m/44'/111111'/0'/0/${index}`;
      const node = root.derive(path);
      if (!node.privateKey || !node.publicKey) throw new Error("no key");
      const tweaked = btc.p2tr(node.publicKey.slice(1)).tweakedPubkey;
      kaspaCases.push({
        mnemonic: s.mnemonic,
        passphrase: s.passphrase,
        options: { network: net.id, encoding: "onekey" },
        style: "standard",
        index,
        path,
        address: kaspaAddress(net.prefix, 0, tweaked),
        public_key: hex(tweaked),
        private_key: hex(node.privateKey),
      });
    }
}
emitCounted(
  "kaspa",
  file(
    "kaspa",
    "@scure/bip32 2.4.0 key material; addresses encoded per the kaspa cashaddr spec — encoder verified byte-for-byte by vectors/kaspa-address.json (official rusty-kaspa vectors); onekey cases: @scure/btc-signer 2.4.1 p2tr(xOnly).tweakedPubkey",
    kaspaCases
  )
);

// nostr — nostr-tools nip06 + nip19
const nostrCases: Case[] = [];
for (const s of SEEDS)
  for (const index of INDICES) {
    const sk: string = privateKeyFromSeedWords(s.mnemonic, s.passphrase, index, 0);
    const pk: string = nostrGetPublicKey(sk);
    nostrCases.push({
      mnemonic: s.mnemonic,
      passphrase: s.passphrase,
      style: "nip06",
      index,
      path: `m/44'/1237'/${index}'/0/0`,
      address: nip19.npubEncode(pk),
      public_key: pk,
      private_key: nip19.nsecEncode(sk),
    });
  }
emitCounted("nostr", file("nostr", "nostr-tools 2.25.2 nip06/nip19", nostrCases));

// spark — @scure/bip32 keys + official @buildonspark/spark-sdk address encoder
const sparkCases: Case[] = [];
for (const s of SEEDS) {
  const root = bip32Root(s);
  for (const net of [
    { id: "mainnet", sdk: "MAINNET" as const, start: 1 },
    { id: "regtest", sdk: "REGTEST" as const, start: 0 },
  ])
    for (const index of INDICES) {
      const path = `m/8797555'/${index}'/0'`;
      const node = root.derive(path);
      if (!node.privateKey || !node.publicKey) throw new Error("no key");
      sparkCases.push({
        mnemonic: s.mnemonic,
        passphrase: s.passphrase,
        options: { network: net.id },
        style: "standard",
        index,
        path,
        address: encodeSparkAddress({
          identityPublicKey: hex(node.publicKey),
          network: net.sdk,
        }),
        public_key: hex(node.publicKey),
        private_key: hex(node.privateKey),
      });
    }
}
emitCounted(
  "spark",
  file("spark", "@scure/bip32 2.4.0 + @buildonspark/spark-sdk 0.13.0 encoder", sparkCases)
);

// casper — @scure/bip32 keys + casper-js-sdk PublicKey account hash
const casperCases: Case[] = [];
for (const s of SEEDS) {
  const root = bip32Root(s);
  for (const index of INDICES) {
    const path = `m/44'/506'/0'/0/${index}`;
    const node = root.derive(path);
    if (!node.privateKey || !node.publicKey) throw new Error("no key");
    const pk = CasperPublicKey.newPublicKey("02" + hex(node.publicKey));
    casperCases.push({
      mnemonic: s.mnemonic,
      passphrase: s.passphrase,
      style: "standard",
      index,
      path,
      address: pk.toHex(false),
      public_key: hex(node.publicKey),
      private_key: hex(node.privateKey),
      extra: { account_hash: pk.accountHash().toPrefixedString() },
    });
  }
}
emitCounted("casper", file("casper", "@scure/bip32 2.4.0 + casper-js-sdk 5.1.1", casperCases));

// sol — micro-key-producer slip10 + @solana/web3.js
const SOL_STYLES = [
  { id: "bip44-change", tpl: (i: number) => `m/44'/501'/${i}'/0'` },
  { id: "bip44", tpl: (i: number) => `m/44'/501'/${i}'` },
];
const solCases: Case[] = [];
for (const s of SEEDS) {
  const root = slip10Root(s);
  for (const style of SOL_STYLES)
    for (const index of INDICES) {
      const path = style.tpl(index);
      const node = root.derive(path);
      const kp = Keypair.fromSeed(node.privateKey);
      solCases.push({
        mnemonic: s.mnemonic,
        passphrase: s.passphrase,
        style: style.id,
        index,
        path,
        address: kp.publicKey.toBase58(),
        public_key: hex(kp.publicKey.toBytes()),
        private_key: bs58.encode(kp.secretKey),
      });
    }
}
// `root` — Ledger Live `solanaMain` derivation mode, a single non-iterating
// account at m/44'/501'.
for (const s of SEEDS) {
  const node = slip10Root(s).derive("m/44'/501'");
  const kp = Keypair.fromSeed(node.privateKey);
  solCases.push({
    mnemonic: s.mnemonic,
    passphrase: s.passphrase,
    style: "root",
    index: null,
    path: "m/44'/501'",
    address: kp.publicKey.toBase58(),
    public_key: hex(kp.publicKey.toBytes()),
    private_key: bs58.encode(kp.secretKey),
  });
}
emitCounted(
  "solana",
  file("solana", "micro-key-producer 0.10.2 slip10 + @solana/web3.js 1.99.0 Keypair", solCases)
);

// sui — @mysten/sui Ed25519Keypair
const suiCases: Case[] = [];
for (const s of SEEDS)
  for (const index of INDICES) {
    const path = `m/44'/784'/${index}'/0'/0'`;
    const kp =
      s.passphrase === ""
        ? Ed25519Keypair.deriveKeypair(s.mnemonic, path)
        : Ed25519Keypair.fromSecretKey(slip10Root(s).derive(path).privateKey);
    suiCases.push({
      mnemonic: s.mnemonic,
      passphrase: s.passphrase,
      style: "standard",
      index,
      path,
      address: kp.getPublicKey().toSuiAddress(),
      public_key: hex(kp.getPublicKey().toRawBytes()),
      private_key: kp.getSecretKey(),
    });
  }
emitCounted(
  "sui",
  file(
    "sui",
    "@mysten/sui 2.35.0 Ed25519Keypair.deriveKeypair (passphrase case: micro-key-producer 0.10.2 slip10 + fromSecretKey)",
    suiCases
  )
);

// aptos — @aptos-labs/ts-sdk Account.fromDerivationPath / fromPrivateKey
const aptosCases: Case[] = [];
for (const s of SEEDS)
  for (const index of INDICES) {
    const path = `m/44'/637'/${index}'/0'/0'`;
    const account =
      s.passphrase === ""
        ? AptosAccount.fromDerivationPath({ path, mnemonic: s.mnemonic })
        : AptosAccount.fromPrivateKey({
            privateKey: new Ed25519PrivateKey(slip10Root(s).derive(path).privateKey),
          });
    aptosCases.push({
      mnemonic: s.mnemonic,
      passphrase: s.passphrase,
      style: "standard",
      index,
      path,
      address: account.accountAddress.toString(),
      public_key: account.publicKey.toUint8Array
        ? hex(account.publicKey.toUint8Array())
        : hex(unhex(account.publicKey.toString())),
      private_key: account.privateKey.toAIP80String(),
    });
  }
emitCounted(
  "aptos",
  file(
    "aptos",
    "@aptos-labs/ts-sdk 7.5.0 Account.fromDerivationPath (passphrase case: micro-key-producer 0.10.2 slip10 + Ed25519PrivateKey)",
    aptosCases
  )
);

// ton — micro-key-producer slip10 + @ton/ton wallet contracts
const tonCases: Case[] = [];
for (const s of SEEDS) {
  const root = slip10Root(s);
  for (const style of [
    { id: "standard", tpl: (i: number) => `m/44'/607'/${i}'` },
    { id: "ledger-live", tpl: (i: number) => `m/44'/607'/0'/0'/${i}'/0'` },
  ])
    for (const contract of [
      { id: "v4r2" },
      { id: "v5r1" },
    ])
      for (const testnet of [false, true])
        for (const bounceable of [false, true])
          for (const index of INDICES) {
            const path = style.tpl(index);
            const node = root.derive(path);
            const publicKey = Buffer.from(node.publicKey.slice(1));
            const wallet =
              contract.id === "v4r2"
                ? WalletContractV4.create({ workchain: 0, publicKey })
                : WalletContractV5R1.create({
                    publicKey,
                    walletId: { networkGlobalId: testnet ? -3 : -239 },
                  });
            tonCases.push({
              mnemonic: s.mnemonic,
              passphrase: s.passphrase,
              options: {
                contract: contract.id,
                testnet,
                bounceable,
              },
              style: style.id,
              index,
              path,
              address: wallet.address.toString({
                urlSafe: true,
                bounceable,
                testOnly: testnet,
              }),
              public_key: hex(node.publicKey.slice(1)),
              private_key: hex(node.privateKey),
            });
          }
}
emitCounted(
  "ton",
  file(
    "ton",
    "micro-key-producer 0.10.2 slip10 + @ton/ton 16.3.0 WalletContractV4/WalletContractV5R1",
    tonCases
  )
);

// xlm — micro-key-producer slip10 + @stellar/stellar-sdk StrKey
const xlmCases: Case[] = [];
for (const s of SEEDS) {
  const root = slip10Root(s);
  for (const index of INDICES) {
    const path = `m/44'/148'/${index}'`;
    const node = root.derive(path);
    const pk = node.publicKey.slice(1);
    xlmCases.push({
      mnemonic: s.mnemonic,
      passphrase: s.passphrase,
      style: "sep5",
      index,
      path,
      address: StrKey.encodeEd25519PublicKey(Buffer.from(pk)),
      public_key: hex(pk),
      private_key: StrKey.encodeEd25519SecretSeed(Buffer.from(node.privateKey)),
    });
  }
}
emitCounted(
  "stellar",
  file("stellar", "micro-key-producer 0.10.2 slip10 + @stellar/stellar-sdk 17.2.1 StrKey", xlmCases)
);

// near — near-seed-phrase parseSeedPhrase; passphrase case: micro-key-producer
// slip10 + ed25519: base58 formatting assembled here
const nearCases: Case[] = [];
for (const s of SEEDS) {
  const root = slip10Root(s);
  for (const style of [
    { id: "standard", tpl: (i: number) => `m/44'/397'/${i}'` },
    { id: "ledger-live", tpl: (i: number) => `m/44'/397'/0'/0'/${i}'` },
  ])
    for (const index of INDICES) {
      const path = style.tpl(index);
      let publicKey: string, secretKey: string, pkBytes: Uint8Array;
      if (s.passphrase === "") {
        const r = parseSeedPhrase(s.mnemonic, path);
        publicKey = r.publicKey;
        secretKey = r.secretKey;
        pkBytes = bs58.decode(r.publicKey.split(":")[1]);
      } else {
        const node = root.derive(path);
        pkBytes = node.publicKey.slice(1);
        publicKey = "ed25519:" + bs58.encode(pkBytes);
        secretKey =
          "ed25519:" + bs58.encode(new Uint8Array([...node.privateKey, ...pkBytes]));
      }
      nearCases.push({
        mnemonic: s.mnemonic,
        passphrase: s.passphrase,
        style: style.id,
        index,
        path,
        address: hex(pkBytes),
        public_key: publicKey,
        private_key: secretKey,
      });
    }
}
emitCounted(
  "near",
  file(
    "near",
    "near-seed-phrase 0.2.1 parseSeedPhrase (passphrase case: micro-key-producer 0.10.2 slip10 + ed25519: base58 formatting)",
    nearCases
  )
);

// ada — CIP-3 masters: icarus via CSL from_bip39_entropy; ledger and
// icarus-trezor computed here per CIP-3 (self-checked against cip3.json
// below before use), then CSL Bip32PrivateKey.from_bytes + V2 derives,
// BaseAddress/RewardAddress bech32. private_key is CIP-5 addr_xsk bech32
// (no length limit) over the 96-byte xprv.
const adaTweak = (d: Uint8Array, icarus: boolean) => {
  d[0] &= 0xf8;
  d[31] &= icarus ? 0x1f : 0x7f;
  d[31] |= 0x40;
  return d;
};
const icarusMaster = (entropy: Uint8Array, passphrase: string) =>
  adaTweak(pbkdf2(sha512, passphrase, entropy, { c: 4096, dkLen: 96 }), true);
const icarusTrezorMaster = (entropy: Uint8Array, passphrase: string) => {
  if (entropy.length !== 32) return icarusMaster(entropy, passphrase);
  // Trezor quirk (CIP-3 / trezor-firmware#1388): the 24-word checksum byte
  // is passed along with the entropy as the PBKDF2 salt.
  const salt = concatBytes(entropy, sha256(entropy).slice(0, 1));
  return adaTweak(pbkdf2(sha512, passphrase, salt, { c: 4096, dkLen: 96 }), true);
};
const ledgerMaster = (seed: Uint8Array) => {
  const key = new TextEncoder().encode("ed25519 seed");
  const cc = hmac(sha256, key, concatBytes(new Uint8Array([1]), seed));
  let i = hmac(sha512, key, seed);
  while (i[31] & 0x20) i = hmac(sha512, key, i);
  return adaTweak(concatBytes(i, cc), false);
};

const adaMaster = (id: string, mnemonic: string, passphrase: string): Uint8Array => {
  const entropy = mnemonicToEntropy(mnemonic, wordlist);
  if (id === "ledger") return ledgerMaster(seedOf({ mnemonic, passphrase }));
  if (id === "icarus-trezor") return icarusTrezorMaster(entropy, passphrase);
  return icarusMaster(entropy, passphrase);
};

// Self-check: the in-generator CIP-3 implementation must reproduce every
// official master/derived vector before it is used for ledger/icarus-trezor.
{
  const cip3 = JSON.parse(readFileSync("../../vectors/cip3.json", "utf8"));
  for (const c of cip3.cases) {
    const master = adaMaster(c.master, c.mnemonic, c.passphrase);
    if (c.xprv) {
      if (hex(master) !== c.xprv)
        throw new Error(`cip3 mismatch: ${c.master} ${c.mnemonic.slice(0, 20)}`);
      continue;
    }
    let node = CSL.Bip32PrivateKey.from_bytes(master);
    for (const i of c.derive) node = node.derive(i);
    const b = node.as_bytes();
    if (
      hex(b.slice(0, 32)) !== c.private_key ||
      hex(b.slice(32, 64)) !== c.extension ||
      hex(b.slice(64, 96)) !== c.chain_code ||
      hex(node.to_public().to_raw_key().as_bytes()) !== c.public_key
    )
      throw new Error(`cip3 derived mismatch: ${c.master}`);
  }
}

const adaCases: Case[] = [];
for (const s of SEEDS)
  for (const master of ["icarus", "ledger", "icarus-trezor"]) {
    const root =
      master === "icarus"
        ? CSL.Bip32PrivateKey.from_bip39_entropy(
            mnemonicToEntropy(s.mnemonic, wordlist),
            new TextEncoder().encode(s.passphrase)
          )
        : CSL.Bip32PrivateKey.from_bytes(adaMaster(master, s.mnemonic, s.passphrase));
    for (const network of ["mainnet", "testnet"]) {
      const netId = network === "mainnet" ? 1 : 0;
      for (const index of INDICES) {
        const path = `m/1852'/1815'/${index}'/0/0`;
        const payKey = root
          .derive(0x80000000 + 1852)
          .derive(0x80000000 + 1815)
          .derive(0x80000000 + index)
          .derive(0)
          .derive(0);
        const stakeKey = root
          .derive(0x80000000 + 1852)
          .derive(0x80000000 + 1815)
          .derive(0x80000000 + index)
          .derive(2)
          .derive(0);
        const payHash = payKey.to_public().to_raw_key().hash();
        const stakeHash = stakeKey.to_public().to_raw_key().hash();
        const address = CSL.BaseAddress.new(
          netId,
          CSL.Credential.from_keyhash(payHash),
          CSL.Credential.from_keyhash(stakeHash)
        )
          .to_address()
          .to_bech32();
        const stake_address = CSL.RewardAddress.new(
          netId,
          CSL.Credential.from_keyhash(stakeHash)
        )
          .to_address()
          .to_bech32();
        adaCases.push({
          mnemonic: s.mnemonic,
          passphrase: s.passphrase,
          options: { master, network },
          style: "standard",
          index,
          path,
          address,
          public_key: hex(payKey.to_public().to_raw_key().as_bytes()),
          private_key: bech32.encode(
            "addr_xsk",
            bech32.toWords(payKey.as_bytes()),
            false
          ),
          extra: { stake_address },
        });
      }
    }
  }
emitCounted(
  "cardano",
  file(
    "cardano",
    "@emurgo/cardano-serialization-lib-nodejs 17.0.0 (icarus: from_bip39_entropy; ledger/icarus-trezor: CIP-3 master computed in-generator and asserted against vectors/cip3.json) + @scure/base 2.4.0 bech32 addr_xsk",
    adaCases
  )
);

for (const [name, count] of counts) console.log(`${name}: ${count} cases`);
