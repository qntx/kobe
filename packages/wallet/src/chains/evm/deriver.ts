import { createDerivedAccount, type DerivedAccount } from "../../hd/account.ts";
import { assertU32Index, deriveRange, type ChainDeriver } from "../../hd/derive.ts";
import type { Wallet } from "../../hd/wallet.ts";
import { wipeBytes } from "../../secret/dispose.ts";
import { evmAddressFromUncompressed } from "./address.ts";
import { evmPath, type EvmDerivationStyle } from "./style.ts";

export interface EvmDeriver extends ChainDeriver<DerivedAccount> {
  deriveWith(style: EvmDerivationStyle, index: number): DerivedAccount;
  deriveManyWith(style: EvmDerivationStyle, start: number, count: number): DerivedAccount[];
}

class EvmDeriverImpl implements EvmDeriver {
  readonly #wallet: Wallet;

  constructor(wallet: Wallet) {
    this.#wallet = wallet;
  }

  derive(index: number): DerivedAccount {
    return this.deriveWith("standard", index);
  }

  deriveAt(path: string): DerivedAccount {
    const key = this.#wallet.deriveSecp256k1(path);
    const sk = key.privateKeyBytes();
    try {
      const uncompressed = key.uncompressedPublicKey();
      const address = evmAddressFromUncompressed(uncompressed);
      return createDerivedAccount({
        path,
        privateKey: sk,
        publicKey: { kind: "secp256k1-uncompressed", bytes: uncompressed },
        address,
      });
    } finally {
      wipeBytes(sk);
      key.dispose();
    }
  }

  deriveWith(style: EvmDerivationStyle, index: number): DerivedAccount {
    return this.deriveAt(evmPath(style, assertU32Index(index, "index")));
  }

  deriveMany(start: number, count: number): DerivedAccount[] {
    return deriveRange(start, count, (i) => this.derive(i));
  }

  deriveManyWith(style: EvmDerivationStyle, start: number, count: number): DerivedAccount[] {
    return deriveRange(start, count, (i) => this.deriveWith(style, i));
  }
}

/** Infallible. Holds a live Wallet reference; does not copy seed. */
export function createEvmDeriver(wallet: Wallet): EvmDeriver {
  return new EvmDeriverImpl(wallet);
}
