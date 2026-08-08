# Kobe chain API contract

Every `kobe-<chain>` deriver follows the same surface. Prefer this table when
adding a chain or reviewing API diffs.

## Construction

| Method | Contract |
| --- | --- |
| `Deriver::new(wallet) -> Self` | Infallible. Optional network/format via args or `with_*`. |
| `Deriver::new(wallet, network) -> Self` | BTC: network is a required second argument. |
| `with_config` / `with_network` / `with_format` | Chain-specific configuration; still infallible. |

Do **not** return `Result` from `new` unless initialization can fail for a real reason.

## Derivation

| Method | Contract |
| --- | --- |
| `derive(index)` | Default path / style for the chain. |
| `derive_at(path: &str)` | Arbitrary BIP-32 / SLIP-10 path (inherent). |
| `Derive::derive_path` | Trait method; must forward to `derive_at`. |
| `DeriveExt::derive_many(start, count)` | Batch of `derive(index)`. |
| `derive_with(style_or_type, index)` | Only when the chain has a style / address-type axis. |
| `derive_at_with(path, style_or_type)` | Non-standard path + explicit type (BTC). |
| `derive_structured` | Pre-parsed path object (BTC). |

## Account type

| Type | When |
| --- | --- |
| `DerivedAccount` | Default for most chains. |
| `BtcAccount` | Extra WIF + address type + path. |
| `SvmAccount` | Extra keypair base58. |
| `NostrAccount` | Extra `nsec`. |

All account types implement `AsRef<DerivedAccount>` (and usually `Deref`).

## Key material

| Path | Use |
| --- | --- |
| `Wallet::derive_secp256k1` / `derive_ed25519` | Preferred inside chain crates. |
| `Wallet::seed` | **Feature `raw-seed` only** (off by default). |

## Errors

All chains surface `kobe_primitives::DeriveError` only (`Path`, `Crypto`,
`Input`, `AddressEncoding`, `Mnemonic`).

## Naming notes

- Inherent method: `derive_at`
- Trait method: `derive_path` (forwards to `derive_at`)
- Do not reintroduce `derive_at_path` / `derive_bip32_path`
