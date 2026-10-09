# kobe-vault

Versioned AES-256-GCM envelope encryption and key derivation for the Kobe
workspace. `no_std` + `alloc`; `std` (default) is additive.

## Envelope v1

- AES-256-GCM, 96-bit nonce drawn from the caller's RNG, 128-bit tag.
- `key` is exactly 32 bytes; `context` is a non-empty UTF-8 string chosen by
  the application (e.g. `example-app/v1/<record-id>/<type>`).
- AAD = `[0x01] || UTF-8(context)` — the version byte is bound into the AAD.
- Sealed bytes = `[0x01] || nonce(12) || ciphertext || tag(16)`; minimum
  length 29 (empty plaintext is allowed).

## API

| Function         | Purpose                                                        |
| ---------------- | -------------------------------------------------------------- |
| `seal` / `open`  | Envelope encrypt / decrypt                                     |
| `password_key`   | PBKDF2-HMAC-SHA256 over `UTF-8(NFKC(password))`, 32-byte key   |
| `prf_key`        | HKDF-SHA256 over a 32-byte PRF output (e.g. WebAuthn PRF)      |
| `passkey_wallet` | `Wallet::from_entropy(prf[0..16])` for passkey-derived wallets |

`PASSWORD_ITERATIONS` (`600_000`) is the recommended PBKDF2 iteration count.
Error codes are shared with the TypeScript `@qntx/kobe/vault`
implementation: `input`, `decrypt`, `version`, `crypto`, `mnemonic`.
