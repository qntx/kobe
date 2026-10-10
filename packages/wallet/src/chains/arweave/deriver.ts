import { createDerivedAccount, type DerivedAccount } from "../../hd/account.ts";
import { assertU32Index, deriveRange, type ChainDeriver } from "../../hd/derive.ts";
import type { Wallet } from "../../hd/wallet.ts";
import { wipeBytes } from "../../secret/dispose.ts";
import { arweaveAddressFromCompressed, arweavePath } from "./address.ts";

export type ArweaveDeriver = ChainDeriver<DerivedAccount>;

class ArweaveDeriverImpl implements ArweaveDeriver {
  readonly #wallet: Wallet;

  constructor(wallet: Wallet) {
    this.#wallet = wallet;
  }

  derive(index: number): DerivedAccount {
    return this.deriveAt(arweavePath(assertU32Index(index, "index")));
  }

  deriveAt(path: string): DerivedAccount {
    const key = this.#wallet.deriveSecp256k1(path);
    const sk = key.privateKeyBytes();
    const pk = key.compressedPublicKey();
    try {
      return createDerivedAccount({
        path,
        privateKey: sk,
        publicKey: { kind: "secp256k1-compressed", bytes: pk },
        address: arweaveAddressFromCompressed(pk),
      });
    } finally {
      wipeBytes(sk);
      key.dispose();
    }
  }

  deriveMany(start: number, count: number): DerivedAccount[] {
    return deriveRange(start, count, (i) => this.derive(i));
  }
}

/** Infallible. ECDSA only — RSA is out of scope. */
export function createArweaveDeriver(wallet: Wallet): ArweaveDeriver {
  return new ArweaveDeriverImpl(wallet);
}
