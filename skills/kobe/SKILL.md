---
name: kobe
description: >-
  Offline HD wallet generator CLI for deriving keys and addresses across 20
  chains: Bitcoin, Litecoin, Dogecoin, Bitcoin Cash, EVM, TRON, Cosmos, XRP,
  Filecoin, Kaspa, Nostr, Spark, Casper, Solana, Sui, Aptos, TON, Stellar,
  NEAR, and Cardano. Use when the user asks to generate wallets, derive
  addresses, import BIP-39 mnemonics, produce NIP-19 npub/nsec identities,
  Shelley addr/stake addresses, or compare derivation styles for Ledger
  Live/Trezor/OneKey compatibility. Supports JSON output via --json.
---

# kobe — offline HD wallet generator

`kobe` is a single binary that turns a BIP-39 mnemonic into keys and addresses
for 20 chains. It is fully offline: no network, no storage, no signing.

## Install

```sh
cargo install kobe-cli   # provides the `kobe` binary
```

## CLI structure

```text
kobe [--json] [-r|--reveal] <COMMAND>
kobe mnemonic [-w 12|15|18|21|24]
kobe <chain> [-m PHRASE|-] [-w N] [-p PASSPHRASE] [-s STYLE | --path TEMPLATE] [-i INDEX] [-c COUNT] [chain flags]
```

- Without `-m` the command generates a fresh mnemonic; `-m -` reads exactly one
  line from stdin.
- `-m` accepts unique ≥4-letter BIP-39 word prefixes (`abando abando … about`
  works).
- `-s` takes a style id or alias, case-insensitive; `--path` takes a template
  with `{i}` for the iterated index and conflicts with `-s`.
- `-i` defaults to the style's start index; `-c` defaults to 1.
- **Secrets are hidden by default**: mnemonic and private keys render as
  `<hidden>` unless `-r/--reveal` is passed. `kobe mnemonic` always prints the
  phrase (it is the output).
- `--json` is global. Errors in JSON mode are `{"error": "…"}` on stdout with
  exit code 1.

## Commands and aliases

| Chain | Command | Aliases | Chain flags |
| ----- | ------- | ------- | ----------- |
| Bitcoin | `bitcoin` | `btc` | `--type p2pkh\|p2sh-p2wpkh\|p2wpkh\|p2tr`, `--network mainnet\|testnet\|regtest` |
| Litecoin | `litecoin` | `ltc` | `--type p2pkh\|p2sh-p2wpkh\|p2wpkh` |
| Dogecoin | `dogecoin` | `doge` | |
| Bitcoin Cash | `bitcoin-cash` | `bch` | |
| EVM | `evm` | `eth`, `ethereum` | |
| TRON | `tron` | `trx` | |
| Cosmos | `cosmos` | `atom` | `--chain <preset>`, `--hrp <prefix>` |
| XRP Ledger | `xrpl` | `xrp` | |
| Filecoin | `filecoin` | `fil` | `--network mainnet\|testnet` |
| Kaspa | `kaspa` | `kas` | `--network mainnet\|testnet`, `--encoding standard\|onekey` |
| Nostr | `nostr` | | |
| Spark | `spark` | | `--network mainnet\|regtest` (mainnet starts at index 1) |
| Casper | `casper` | `cspr` | |
| Solana | `solana` | `sol` | |
| Sui | `sui` | | |
| Aptos | `aptos` | `apt` | |
| TON | `ton` | | `--contract v4r2\|v5r1`, `--testnet`, `--bounceable` |
| Stellar | `stellar` | `xlm` | |
| NEAR | `near` | | |
| Cardano | `cardano` | `ada` | `--network mainnet\|testnet`, `--master icarus\|ledger\|icarus-trezor` |

Cosmos `--chain` presets: `cosmos osmosis celestia dydx sei akash terra secret
kava injective evmos`; `--hrp` overrides only the bech32 prefix.

Cardano `--master` selects the CIP-3 master-key algorithm (`icarus` =
Yoroi/Daedalus Shelley and Trezor <24 words, `ledger` = Ledger devices,
`icarus-trezor` = Trezor 24 words). Cardano custom paths must keep the
`m/1852'/1815'/a'/0/n` shape; the stake address is always emitted in `extra`.

## Styles

Each chain's `--help` lists its styles with template and compatible wallets.
Notable ids: `standard`/`account` (alias `ledger-live`) on the BIP-32 family,
`ledger-live`/`ledger-legacy`(`mew`) on EVM, `bip44-change`(`phantom`),
`bip44`(`trust`), and `root` (Ledger Live `solanaMain`, non-iterating
`m/44'/501'`) on Solana, `nip06` on Nostr, `sep5` on Stellar. Kaspa
`--encoding onekey` addresses carry the BIP-341-tweaked x-only key (the
exported `private_key` stays the untweaked raw key).

## JSON output

```json
{
  "chain": "cardano",
  "options": { "master": "icarus", "network": "mainnet" },
  "style": "standard",
  "template": "m/1852'/1815'/{i}'/0/0",
  "mnemonic": "...",          // only with --reveal
  "passphrase": false,
  "accounts": [
    {
      "index": 0,             // null when the template has no {i}
      "path": "m/1852'/1815'/0'/0/0",
      "address": "addr1…",
      "public_key": "…",
      "private_key": "…",     // only with --reveal
      "stake_address": "stake1…"   // chain extras are flattened per account
    }
  ]
}
```

## Examples

```sh
kobe mnemonic -w 24
kobe bitcoin -m "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
kobe bitcoin -m - --reveal                   # mnemonic from stdin
kobe evm -s ledger-live -c 5
kobe cosmos --chain injective -c 3 --json
kobe kaspa --encoding onekey
kobe solana -s root
kobe cardano --network testnet --master ledger
kobe --json ton --contract v5r1 --testnet
```

## Safety notes

- Prefer `-m -` (stdin) or generation over `-m PHRASE` — a literal mnemonic on
  the command line lands in shell history.
- `--reveal` prints raw secrets to the terminal; combine with `--json` only
  when piping to a trusted consumer.
