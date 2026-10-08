# @qntx/kobe

Multi-chain HD wallet SDK in TypeScript — the TypeScript twin of the `kobe-*`
Rust crates. Capabilities shared with Rust are tracked in
[`parity.json`](../../parity.json) and tested against the same vectors in
[`vectors/`](../../vectors/).

## Subpaths

The package is subpath-only; there is no root entry.

### `@qntx/kobe/core`

BIP-39 / BIP-32 wallet core:

- `Wallet` — holds a normalized English mnemonic and the 64-byte BIP-39 seed
  in a module-scoped `WeakMap`. Construct with `Wallet.generate()`,
  `Wallet.fromMnemonic(phrase, passphrase?)`,
  `Wallet.fromMnemonicExpanded(phrase, passphrase?)` (English 4-letter prefix
  expansion), or `Wallet.fromEntropy(entropy, passphrase?)`. `wordCount`,
  `hasPassphrase`, `mnemonic()`, `mnemonicBytes()`,
  `deriveSecp256k1(path)` and `dispose()` (wipes both buffers; later access
  throws `KobeError("input")`). `toString()` / `toJSON()` are redacted;
  secrets live in private state, so `util.inspect` never shows them.
- `isValidMnemonic(phrase)`, `expandMnemonic(phrase)`.
- Types: `KobeError` (`code: KobeErrorCode`), `GenerateWalletOptions`,
  `WordCount`, `DerivedSecp256k1Key`, `DerivedAccount`, `DerivedPublicKey`.

### `@qntx/kobe/nostr`

NIP-06 Nostr derivation:

- `NostrDeriver` — `new NostrDeriver(wallet)`, `derive(account)`,
  `deriveAt(path)`, `deriveMany(start, count)`.
- `NostrAccount` — `DerivedAccount` plus `nsec()` / `npub()` (NIP-19).

## Runtime requirements

Platform-neutral (Node, browsers, Hermes): the library expects
`TextEncoder` and `String.prototype.normalize` (NFKD) to exist.
`crypto.getRandomValues` is required only by `Wallet.generate` without a
custom `rng` option.

## License

MIT OR Apache-2.0
