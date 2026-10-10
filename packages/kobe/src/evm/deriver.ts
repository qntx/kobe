import { createDerivedAccount } from "../core/account.ts";
import type { DerivedAccount } from "../core/account.ts";
import { wipeBytes } from "../core/bytes.ts";
import { assertU32Index, deriveRange } from "../core/derive.ts";
import type { Wallet } from "../core/wallet.ts";
import { addressFromUncompressed } from "./address.ts";
import { evmPath } from "./style.ts";
import type { EvmDerivationStyle } from "./style.ts";

/**
 * EVM account deriver from a unified wallet — `kobe_evm::Deriver` analog.
 *
 * `index` maps to `m/44'/60'/0'/0/{index}` (MetaMask/BIP-44 "standard"); Ledger styles move the
 * index up the path. Addresses are EIP-55 checksummed.
 */
export class EvmDeriver {
  readonly #wallet: Wallet;

  constructor(wallet: Wallet) {
    this.#wallet = wallet;
  }

  /**
   * Derive in the "standard" style.
   *
   * @throws KobeError input (index range) | path | crypto | address-encoding
   */
  derive(index: number): DerivedAccount {
    return this.deriveWith("standard", index);
  }

  /**
   * @throws KobeError input (index range) | path | crypto | address-encoding | input if wallet is
   *   disposed
   */
  deriveWith(style: EvmDerivationStyle, index: number): DerivedAccount {
    return this.deriveAt(evmPath(style, assertU32Index(index, "index")));
  }

  /**
   * Derive at an explicit path. The account carries a `secp256k1-uncompressed` public key and an
   * EIP-55 checksummed address.
   *
   * @throws KobeError path | crypto | address-encoding | input if wallet is disposed
   */
  deriveAt(path: string): DerivedAccount {
    const key = this.#wallet.deriveSecp256k1(path);
    const sk = key.privateKeyBytes();
    try {
      const uncompressed = key.uncompressedPublicKey();
      return createDerivedAccount({
        path,
        privateKey: sk,
        publicKey: { kind: "secp256k1-uncompressed", bytes: uncompressed },
        address: addressFromUncompressed(uncompressed),
      });
    } finally {
      wipeBytes(sk);
      key.dispose();
    }
  }

  /** @throws KobeError input (range overflow) or any error from `derive` */
  deriveMany(start: number, count: number): DerivedAccount[] {
    return deriveRange(start, count, (i) => this.derive(i));
  }

  /** @throws KobeError input (range overflow) or any error from `deriveWith` */
  deriveManyWith(style: EvmDerivationStyle, start: number, count: number): DerivedAccount[] {
    return deriveRange(start, count, (i) => this.deriveWith(style, i));
  }
}
