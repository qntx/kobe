# @qntx/wallet

Software wallet kernel in TypeScript: HD derivation, protocol-framed
signing, and versioned key-store envelopes. Pure TypeScript (`@noble` /
`@scure`). No RPC, hardware, or UI.

```ts
import { walletFromMnemonic } from "@qntx/wallet/hd";
import { createEvmDeriver, EvmSigner } from "@qntx/wallet/evm";

const wallet = walletFromMnemonic("test test test test test test test test test test test junk");
const evm = createEvmDeriver(wallet).derive(0);
EvmSigner.fromDerived(evm).signMessage(new TextEncoder().encode("hello"));
```

Subpath-only package (no root entry): `@qntx/wallet/hd` (BIP-39/44 wallets,
`hd/raw-seed`, `hd/wordlists`, `hd/camouflage`), `@qntx/wallet/sign`
(secret keys and curve signers), chain modules `@qntx/wallet/evm` (plus
`evm/rlp`), `svm`, `btc`, `nostr`, and `@qntx/wallet/vault` (AES-GCM
envelope, PBKDF2/HKDF KDFs, `passkeyWallet`).

Cross-language parity with the `kobe-*` Rust crates in this repository is
checked against the shared `vectors/` corpus.

Secret-bearing objects implement `Symbol.dispose`, and the library uses
`using` internally. React Native (Hermes) has no `Symbol.dispose`, so install
this before the first import of `@qntx/wallet`:

```ts
const symbols = Symbol as { dispose?: symbol; asyncDispose?: symbol };
symbols.dispose ??= Symbol.for("Symbol.dispose");
symbols.asyncDispose ??= Symbol.for("Symbol.asyncDispose");
```

## License

Licensed under either of the MIT License ([LICENSE-MIT](LICENSE-MIT)) or the
Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)) at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this project shall be dual-licensed as above,
without any additional terms or conditions.

---

<div align="center">

A **[QuantX](https://qntx.org)** open-source project.

<a href="https://qntx.org"><img alt="QuantX" width="369" src="https://raw.githubusercontent.com/qntx/.github/main/profile/qntx.svg" /></a>

Code is law. We write both.

</div>
