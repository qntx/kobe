<!-- markdownlint-disable MD033 MD041 -->

# kobe

Pure, offline BIP-39 HD wallet **generator** in Rust: mnemonic → keys → addresses
for 20 chains. `no_std + alloc` library plus a `kobe` CLI. No signing, no vault,
no storage, no network — kobe derives keys and addresses, nothing else.

## Install

```sh
cargo install kobe-cli    # installs the `kobe` binary
```

Pre-built binaries for macOS, Linux, and Windows are attached to every
[GitHub release](https://github.com/qntx/kobe/releases).

## CLI quick start

```sh
kobe mnemonic -w 24                 # fresh 24-word BIP-39 phrase
kobe btc -m "abandon … about"       # derive from an existing mnemonic
kobe btc -m - --reveal              # read the mnemonic from stdin, show secrets
kobe evm -s ledger-live -c 3        # 3 Ledger-Live-style accounts
kobe ada --network testnet --master ledger --json
```

Every chain command shares the same flags:

| Flag                  | Description                                                        |
| --------------------- | ------------------------------------------------------------------ |
| `-m, --mnemonic`      | Import a mnemonic; `-` reads one line from stdin. Words may be unique ≥4-letter BIP-39 prefixes. |
| `-w, --words`         | Word count when generating: 12/15/18/21/24 (conflicts with `-m`).  |
| `-p, --passphrase`    | BIP-39 passphrase.                                                 |
| `-s, --style`         | Style id or alias, case-insensitive (see table below).             |
| `--path`              | Custom path template; `{i}` marks the iterated index (conflicts with `-s`). |
| `-i, --index`         | First iterated index (defaults to the style's `start`).            |
| `-c, --count`         | Number of accounts (default 1).                                    |
| `--json`              | Machine-readable output; errors are `{"error": "…"}` on stdout, exit 1. |
| `-r, --reveal`        | Show mnemonic and private keys (hidden by default).                |

Mnemonic and private keys are `<hidden>` unless `--reveal` is passed.

## Chains and styles

`{i}` is the iterated index (the `-i`/`-c` sweep). Aliases are accepted for `-s`.

| Chain | Command | Options | Style | Template | Wallets |
| ----- | ------- | ------- | ----- | -------- | ------- |
| Bitcoin | `btc` (`bitcoin`) | `--type p2pkh\|p2sh-p2wpkh\|p2wpkh\|p2tr`, `--network mainnet\|testnet\|regtest` | `standard` | `m/<p>'/0'/0'/0/{i}` | Sparrow, Electrum, Bitcoin Core, BlueWallet |
| | | | `account` (`ledger-live`) | `m/<p>'/0'/{i}'/0/0` | Ledger Live, Trezor Suite, OneKey |
| Litecoin | `ltc` (`litecoin`) | `--type p2pkh\|p2sh-p2wpkh\|p2wpkh` | `standard` | `m/<p>'/2'/0'/0/{i}` | Sparrow, Electrum-LTC, LoafWallet |
| | | | `account` (`ledger-live`) | `m/<p>'/2'/{i}'/0/0` | Ledger Live, Trezor Suite, OneKey |
| Dogecoin | `doge` (`dogecoin`) | | `standard` | `m/44'/3'/0'/0/{i}` | Trust Wallet, MyDoge, Doge Core |
| | | | `account` (`ledger-live`) | `m/44'/3'/{i}'/0/0` | Ledger Live, Trezor Suite, OneKey |
| Bitcoin Cash | `bch` (`bitcoincash`) | | `standard` | `m/44'/145'/0'/0/{i}` | Electron Cash |
| | | | `account` (`ledger-live`) | `m/44'/145'/{i}'/0/0` | Ledger Live, OneKey |
| EVM | `evm` (`eth`, `ethereum`) | | `standard` | `m/44'/60'/0'/0/{i}` | MetaMask, Rabby, Trezor, OneKey, Trust Wallet |
| | | | `ledger-live` | `m/44'/60'/{i}'/0/0` | Ledger Live |
| | | | `ledger-legacy` (`mew`) | `m/44'/60'/0'/{i}` | Ledger legacy, MEW, MyCrypto |
| TRON | `tron` (`trx`) | | `standard` | `m/44'/195'/0'/0/{i}` | TronLink, Trust Wallet, OneKey |
| | | | `ledger-live` | `m/44'/195'/{i}'/0/0` | Ledger Live |
| Cosmos | `cosmos` (`atom`) | `--chain <preset>`, `--hrp` | `standard` | `m/44'/118'/0'/0/{i}` | Keplr, Leap, Cosmostation, OneKey |
| | | | `ledger-live` | `m/44'/118'/{i}'/0/0` | Ledger Live |
| XRP | `xrp` (`xrpl`) | | `standard` | `m/44'/144'/0'/0/{i}` | Xaman, xrpl.js |
| | | | `ledger-live` | `m/44'/144'/{i}'/0/0` | Ledger Live, OneKey |
| Filecoin | `fil` (`filecoin`) | `--network mainnet\|testnet` | `standard` | `m/44'/461'/0'/0/{i}` | Glif, Ledger Live, OneKey |
| Kaspa | `kaspa` (`kas`) | `--network mainnet\|testnet` | `standard` | `m/44'/111111'/0'/0/{i}` | Kaspium, KasWare, OneKey |
| Nostr | `nostr` | | `nip06` | `m/44'/1237'/{i}'/0/0` | Damus, Amethyst, Primal, Iris, OneKey |
| Spark | `spark` | `--network mainnet\|regtest` | `standard` | `m/8797555'/{i}'/0'` | Spark wallet SDK (index starts at 1 on mainnet) |
| Casper | `casper` (`cspr`) | | `standard` | `m/44'/506'/0'/0/{i}` | Casper Wallet, Ledger Live |
| Solana | `sol` (`solana`, `svm`) | | `bip44-change` (`phantom`) | `m/44'/501'/{i}'/0'` | Phantom, Solflare, Backpack, OneKey, Solana CLI (`?key=i/0`) |
| | | | `bip44` (`trust`) | `m/44'/501'/{i}'` | Ledger Live, Trust Wallet |
| Sui | `sui` | | `standard` | `m/44'/784'/{i}'/0'/0'` | Slush, Suiet, OneKey, Ledger Live |
| Aptos | `aptos` (`apt`) | | `standard` | `m/44'/637'/{i}'/0'/0'` | Petra, Pontem, OneKey, Ledger Live |
| TON | `ton` | `--contract v4r2\|v5r1`, `--testnet`, `--bounceable` | `standard` | `m/44'/607'/{i}'` | OneKey |
| | | | `ledger-live` | `m/44'/607'/0'/0'/{i}'/0'` | Ledger Live |
| Stellar | `xlm` (`stellar`) | | `sep5` | `m/44'/148'/{i}'` | Lobstr, Freighter, Ledger Live, OneKey |
| NEAR | `near` | | `standard` | `m/44'/397'/{i}'` | MyNearWallet, Meteor, near-cli, OneKey |
| | | | `ledger-live` | `m/44'/397'/0'/0'/{i}'` | Ledger Live |
| Cardano | `ada` (`cardano`) | `--network mainnet\|testnet`, `--master icarus\|ledger\|icarus-trezor` | `standard` | `m/1852'/1815'/{i}'/0/0` | Yoroi, Eternl, Lace, Typhon, Daedalus, Trezor Suite, Ledger Live |

Cosmos presets for `--chain`: `cosmos`, `osmosis`, `celestia`, `dydx`, `sei`,
`akash`, `terra`, `secret`, `kava`, `injective`, `evmos` — each fixes
the BIP-44 coin type and bech32 HRP; `--hrp` overrides only the prefix.

Cardano `--master` selects the CIP-3 master-key algorithm: `icarus`
(Yoroi/Daedalus Shelley, Trezor <24 words), `ledger` (Ledger devices),
`icarus-trezor` (Trezor 24-word mnemonics). Custom `--path` must keep the
`m/1852'/1815'/a'/0/n` shape; the stake key is always derived at
`m/1852'/1815'/a'/2/0` for the same account.

## Output

Every account prints its `path`, `address`, `public_key`, and `private_key`
(the chain's wallet-import encoding):

| Chain | `address` | `private_key` | `extra` |
| ----- | --------- | ------------- | ------- |
| btc / ltc / doge | Base58Check or bech32 (`bc1q…`, `ltc1…`, `D…`) | compressed WIF | |
| bch | CashAddr `bitcoincash:q…` | compressed WIF | |
| evm | EIP-55 `0x…` | `0x` hex | |
| tron | Base58Check `T…` | hex (no prefix) | |
| cosmos | bech32 per preset / `--hrp` | hex | |
| xrp | classic `r…` (XRPL alphabet) | hex | |
| fil | `f1…` / `t1…` (blake2b-160) | Lotus export JSON as hex | |
| kaspa | `kaspa:` / `kaspatest:` (x-only pubkey) | hex | |
| nostr | NIP-19 `npub…` | `nsec…` | |
| spark | bech32m `spark1…` / `sparkrt1…` | hex | |
| casper | tagged pubkey hex `02…` | hex | `account_hash` (`account-hash-…`) |
| sol | base58 pubkey | base58 `sk‖pk` keypair | |
| sui | `0x…` (blake2b-256 with scheme flag) | `suiprivkey1…` bech32 | |
| aptos | `0x…` (sha3-256 with scheme flag) | AIP-80 `ed25519-priv-0x…` | |
| ton | user-friendly base64url `UQ…`/`EQ…` | hex | |
| xlm | StrKey `G…` | StrKey `S…` | |
| near | implicit account = hex pubkey | `ed25519:base58(sk‖pk)` | |
| ada | Shelley base `addr1…` / `addr_test1…` | CIP-5 `addr_xsk1…` | `stake_address` (`stake1…`) |

`--json` emits `{ "chain", "options", "style", "template", "mnemonic"?,
"passphrase", "accounts": [ { "index", "path", "address", "public_key",
"private_key"?, …extra } ] }` — secret fields appear only with `--reveal`.

## Library

```toml
[dependencies]
kobe = { version = "5", features = ["btc"] }   # or "all-chains"
```

```rust
use kobe::btc::{Bitcoin, Kind, Network};
use kobe::{Chain, Wallet};

fn main() -> Result<(), kobe::Error> {
    let wallet = Wallet::from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "",
    )?;
    let btc = Bitcoin::new(Network::Mainnet, Kind::P2wpkh);
    let account = btc.derive(&wallet, &btc.styles()[0].path(0)?)?;
    assert_eq!(account.address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    Ok(())
}
```

`Wallet::generate(rng, words, passphrase)` takes any `rand_core::CryptoRng`;
`Wallet::random` (OS entropy) requires the `os-rng` feature.

### Feature flags

- `std` (default) — `std` conveniences; the crate is `no_std + alloc` without it.
- `os-rng` — OS entropy via `getrandom` for `Wallet::random`.
- `hd-bip32`, `hd-slip10` — derivation engines only.
- One feature per chain: `btc ltc doge bch evm tron cosmos xrp fil kaspa nostr
  spark casper sol sui aptos ton xlm near ada`; `all-chains` enables all of them.

With `--no-default-features` the library builds for `thumbv7m-none-eabi`,
`wasm32-unknown-unknown`, iOS, and Android with no `getrandom` in the graph.

## Security model

- kobe never talks to the network and never persists anything; secrets live in
  `Zeroizing` buffers and are redacted from `Debug`.
- The CLI hides the mnemonic and private keys unless `--reveal` is passed, and
  prints a hint instead.
- `-m PHRASE` puts the mnemonic in your shell history — prefer `-m -` (stdin)
  or run without `-m` to generate.
- Every chain and style is pinned to official or independently generated
  reference vectors in [`vectors/`](vectors), verified byte-for-byte in CI.

## Out of scope

Polkadot/Substrate (sr25519 + substrate-bip39 is not BIP-32/SLIP-10 HD), TON-native
/ Monero / Algorand-native mnemonics, Arweave, the Solana Sollet legacy path,
transaction signing, mnemonic camouflage, and non-English wordlists.

## Related

The stateful self-custodial wallet SDK (vault, sessions, signing) lives at
[qntx/wallet](https://github.com/qntx/wallet). kobe only generates keys and
addresses.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project shall be dual-licensed as above, without any
additional terms or conditions.

---

<div align="center">

A **[QuantX](https://qntx.org)** open-source project.

<a href="https://qntx.org"><img alt="QuantX" width="369" src="https://raw.githubusercontent.com/qntx/.github/main/profile/qntx.svg" /></a>

Code is law. We write both.

</div>
