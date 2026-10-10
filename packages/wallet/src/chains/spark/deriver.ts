import { createDerivedAccount, type DerivedAccount } from "../../hd/account.ts";
import { assertU32Index, deriveRange, type ChainDeriver } from "../../hd/derive.ts";
import type { Wallet } from "../../hd/wallet.ts";
import { wipeBytes } from "../../secret/dispose.ts";
import { encodeSparkAddress, sparkPath, type SparkNetwork } from "./address.ts";

export interface SparkDeriver extends ChainDeriver<DerivedAccount> {
  readonly network: SparkNetwork;
}

class SparkDeriverImpl implements SparkDeriver {
  readonly network: SparkNetwork;
  readonly #wallet: Wallet;

  constructor(wallet: Wallet, network: SparkNetwork) {
    this.#wallet = wallet;
    this.network = network;
  }

  derive(index: number): DerivedAccount {
    return this.deriveAt(sparkPath(assertU32Index(index, "index")));
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
        address: encodeSparkAddress(pk, this.network),
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

/** Infallible. Default network is mainnet (`spark1…`). */
export function createSparkDeriver(
  wallet: Wallet,
  network: SparkNetwork = "mainnet",
): SparkDeriver {
  return new SparkDeriverImpl(wallet, network);
}
