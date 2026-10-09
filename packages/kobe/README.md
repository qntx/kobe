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
  `id()` returns a stable, non-secret wallet identifier — the first 16 hex
  chars of `SHA-256("kobe/wallet-id/v1" ‖ pubkey)`, where `pubkey` is the
  compressed BIP-32 master public key. Identical across the Rust and TS
  implementations (`vectors/core/wallet-id.json`).
- `isValidMnemonic(phrase)`, `expandMnemonic(phrase)`.
- Types: `KobeError` (`code: KobeErrorCode`), `GenerateWalletOptions`,
  `WordCount`, `DerivedSecp256k1Key`, `DerivedAccount`, `DerivedPublicKey`.

### `@qntx/kobe/nostr`

NIP-06 Nostr derivation:

- `NostrDeriver` — `new NostrDeriver(wallet)`, `derive(account)`,
  `deriveAt(path)`, `deriveMany(start, count)`.
- `NostrAccount` — `DerivedAccount` plus `nsec()` / `npub()` (NIP-19); the
  `nsec` string is computed on demand, never held.

### `@qntx/kobe/vault`

Versioned envelope encryption and key derivation (the `@qntx/kobe` twin of
the `kobe-vault` crate):

- `seal(key, plaintext, context, rng?)` / `open(key, sealed, context)` —
  envelope v1: AES-256-GCM, 12-byte nonce from `rng` (defaults to
  `crypto.getRandomValues`), `[0x01] || nonce || ciphertext || tag` bytes,
  and AAD `[0x01] || UTF-8(context)`.
- `derivePasswordKey(password, salt, iterations, pbkdf2?)` — PBKDF2-HMAC-SHA256
  over `UTF-8(NFKC(password))`; async because the default is noble
  `pbkdf2Async` and Web consumers can inject WebCrypto.
- `derivePrfKey(prfOutput, info)` — HKDF-SHA256 over a 32-byte PRF output.
- `passkeyWallet(prfOutput)` — a 12-word `Wallet` from a 32-byte PRF output.
- `VAULT_VERSION` (`1`), `PASSWORD_ITERATIONS` (`600_000`).

## Runtime requirements

Platform-neutral (Node, browsers, Hermes): the library expects
`TextEncoder` and `String.prototype.normalize` (NFKD; NFKC for
`derivePasswordKey`) to exist. `crypto.getRandomValues` is required only by
`Wallet.generate` and `seal` without a custom `rng` option.

## License

MIT OR Apache-2.0
