import { createDerivedAccount, type DerivedAccount } from "../../hd/account.ts";
import { assertU32Index, deriveRange, type ChainDeriver } from "../../hd/derive.ts";
import type { Wallet } from "../../hd/wallet.ts";
import { wipeBytes } from "../../secret/dispose.ts";
import { xrplAddressFromCompressed, xrplPath } from "./address.ts";

export type XrplDeriver = ChainDeriver<DerivedAccount>;

class XrplDeriverImpl implements XrplDeriver {
  readonly #wallet: Wallet;

  constructor(wallet: Wallet) {
    this.#wallet = wallet;
  }

  derive(index: number): DerivedAccount {
    return this.deriveAt(xrplPath(assertU32Index(index, "index")));
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
        address: xrplAddressFromCompressed(pk),
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
export function createXrplDeriver(wallet: Wallet): XrplDeriver {
  return new XrplDeriverImpl(wallet);
}
