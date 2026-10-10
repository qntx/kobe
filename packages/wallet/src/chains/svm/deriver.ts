import type { SvmAccount } from "../../hd/account.ts";
import { assertU32Index, deriveRange } from "../../hd/derive.ts";
import type { ChainDeriver } from "../../hd/derive.ts";
import type { Wallet } from "../../hd/wallet.ts";
import { wipeBytes } from "../../secret/dispose.ts";
import { createSvmAccount } from "./account.ts";
import { svmPath } from "./style.ts";
import type { SvmDerivationStyle } from "./style.ts";

export type SvmDeriver = {
  deriveWith(style: SvmDerivationStyle, index: number): SvmAccount;
  deriveManyWith(style: SvmDerivationStyle, start: number, count: number): SvmAccount[];
} & ChainDeriver<SvmAccount>;

class SvmDeriverImpl implements SvmDeriver {
  readonly #wallet: Wallet;

  constructor(wallet: Wallet) {
    this.#wallet = wallet;
  }

  derive(index: number): SvmAccount {
    return this.deriveWith("bip44-change", index);
  }

  deriveAt(path: string): SvmAccount {
    const key = this.#wallet.deriveEd25519(path);
    const sk = key.privateKeyBytes();
    const pk = key.publicKeyBytes();
    try {
      return createSvmAccount({ path, privateKey: sk, publicKey: pk });
    } finally {
      wipeBytes(sk);
      key.dispose();
    }
  }

  deriveWith(style: SvmDerivationStyle, index: number): SvmAccount {
    return this.deriveAt(svmPath(style, assertU32Index(index, "index")));
  }

  deriveMany(start: number, count: number): SvmAccount[] {
    return deriveRange(start, count, (i) => this.derive(i));
  }

  deriveManyWith(style: SvmDerivationStyle, start: number, count: number): SvmAccount[] {
    return deriveRange(start, count, (i) => this.deriveWith(style, i));
  }
}

/** Infallible. Holds a live Wallet reference; does not copy seed. */
export function createSvmDeriver(wallet: Wallet): SvmDeriver {
  return new SvmDeriverImpl(wallet);
}
