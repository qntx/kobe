import { createDerivedAccount, type DerivedAccount } from "../../hd/account.ts";
import { assertU32Index, deriveRange, type ChainDeriver } from "../../hd/derive.ts";
import type { Wallet } from "../../hd/wallet.ts";
import { wipeBytes } from "../../secret/dispose.ts";
import { TON_ADDRESS_DEFAULT, tonAddressFromPublicKey, type TonAddressFormat } from "./address.ts";
import { tonPath, type TonDerivationStyle } from "./style.ts";

export interface TonDeriver extends ChainDeriver<DerivedAccount> {
  readonly format: TonAddressFormat;
  deriveWith(style: TonDerivationStyle, index: number): DerivedAccount;
  deriveManyWith(style: TonDerivationStyle, start: number, count: number): DerivedAccount[];
}

class TonDeriverImpl implements TonDeriver {
  readonly format: TonAddressFormat;
  readonly #wallet: Wallet;

  constructor(wallet: Wallet, format: TonAddressFormat) {
    this.#wallet = wallet;
    this.format = format;
  }

  derive(index: number): DerivedAccount {
    return this.deriveWith("standard", index);
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
        address: tonAddressFromPublicKey(pk, this.format),
      });
    } finally {
      wipeBytes(sk);
      key.dispose();
    }
  }

  deriveWith(style: TonDerivationStyle, index: number): DerivedAccount {
    return this.deriveAt(tonPath(style, assertU32Index(index, "index")));
  }

  deriveMany(start: number, count: number): DerivedAccount[] {
    return deriveRange(start, count, (i) => this.derive(i));
  }

  deriveManyWith(style: TonDerivationStyle, start: number, count: number): DerivedAccount[] {
    return deriveRange(start, count, (i) => this.deriveWith(style, i));
  }
}

/** Infallible. Default format is mainnet / workchain 0 / non-bounceable. */
export function createTonDeriver(
  wallet: Wallet,
  format: TonAddressFormat = TON_ADDRESS_DEFAULT,
): TonDeriver {
  return new TonDeriverImpl(wallet, format);
}
