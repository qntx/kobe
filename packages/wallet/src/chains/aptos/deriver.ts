import { createDerivedAccount, type DerivedAccount } from "../../hd/account.ts";
import { assertU32Index, deriveRange, type ChainDeriver } from "../../hd/derive.ts";
import type { Wallet } from "../../hd/wallet.ts";
import { wipeBytes } from "../../secret/dispose.ts";
import { aptosAddressFromPublicKey, aptosPath } from "./hash.ts";

export type AptosDeriver = ChainDeriver<DerivedAccount>;

class AptosDeriverImpl implements AptosDeriver {
  readonly #wallet: Wallet;

  constructor(wallet: Wallet) {
    this.#wallet = wallet;
  }

  derive(index: number): DerivedAccount {
    return this.deriveAt(aptosPath(assertU32Index(index, "index")));
  }

  deriveAt(path: string): DerivedAccount {
    const key = this.#wallet.deriveEd25519(path);
    const sk = key.privateKeyBytes();
    const pk = key.publicKeyBytes();
    try {
      return createDerivedAccount({
        path,
        privateKey: sk,
        publicKey: { kind: "ed25519", bytes: pk },
        address: aptosAddressFromPublicKey(pk),
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

export function createAptosDeriver(wallet: Wallet): AptosDeriver {
  return new AptosDeriverImpl(wallet);
}
