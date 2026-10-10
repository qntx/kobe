# wallet.js

Software wallet kernel in TypeScript: HD derivation, protocol-framed
signing, and AES-GCM credential blobs. Pure TypeScript (`@noble` / `@scure`).
No RPC, hardware, or UI.

Package: `@qntx/wallet`.

```ts
import { walletFromMnemonic } from "@qntx/wallet/hd";
import { createEvmDeriver, createEvmSigner } from "@qntx/wallet/evm";
import { encryptMnemonic, decryptMnemonic } from "@qntx/wallet/secret";

const wallet = walletFromMnemonic("test test test test test test test test test test test junk");
const evm = createEvmDeriver(wallet).derive(0);
createEvmSigner(evm).signMessage(new TextEncoder().encode("hello"));

const blob = encryptMnemonic(wallet.mnemonic(), "host-password");
decryptMnemonic(blob, "host-password");
```

Chain modules: `@qntx/wallet/evm`, `svm`, `btc`, `tron`, `cosmos`, `sui`, `aptos`, `nostr`, `ton`, `fil`, `spark`, `xrpl`, `casper`, `arweave`.  
HD extras: `@qntx/wallet/hd/raw-seed`, `hd/wordlists`, `hd/camouflage`. Signing engines: `@qntx/wallet/sign`.

Security: [`SECURITY.md`](../../SECURITY.md).

## License

Licensed under the MIT License ([LICENSE](LICENSE) or <https://opensource.org/licenses/MIT>).

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project shall be licensed as above, without any additional terms or conditions.

---

<div align="center">

A **[QuantX](https://qntx.org)** open-source project.

<a href="https://qntx.org"><img alt="QuantX" width="369" src="https://raw.githubusercontent.com/qntx/.github/main/profile/qntx.svg" /></a>

Code is law. We write both.

</div>
