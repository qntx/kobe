import { createDerivedAccount, type DerivedAccount } from "../../hd/account.ts";
import { assertU32Index, deriveRange, type ChainDeriver } from "../../hd/derive.ts";
import type { Wallet } from "../../hd/wallet.ts";
import { wipeBytes } from "../../secret/dispose.ts";
import { filAddressFromUncompressed, filPath } from "./address.ts";

export type FilDeriver = ChainDeriver<DerivedAccount>;

class FilDeriverImpl implements FilDeriver {
  readonly #wallet: Wallet;

  constructor(wallet: Wallet) {
    this.#wallet = wallet;
  }

  derive(index: number): DerivedAccount {
    return this.deriveAt(filPath(assertU32Index(index, "index")));
  }

  deriveAt(path: string): DerivedAccount {
    const key = this.#wallet.deriveSecp256k1(path);
    const sk = key.privateKeyBytes();
    try {
      const uncompressed = key.uncompressedPublicKey();
      return createDerivedAccount({
        path,
        privateKey: sk,
        publicKey: { kind: "secp256k1-uncompressed", bytes: uncompressed },
        address: filAddressFromUncompressed(uncompressed),
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

/** Infallible. Holds a live Wallet reference; does not copy seed. */
export function createFilDeriver(wallet: Wallet): FilDeriver {
  return new FilDeriverImpl(wallet);
}
