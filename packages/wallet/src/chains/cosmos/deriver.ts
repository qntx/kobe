import { createDerivedAccount, type DerivedAccount } from "../../hd/account.ts";
import { assertU32Index, deriveRange, type ChainDeriver } from "../../hd/derive.ts";
import type { Wallet } from "../../hd/wallet.ts";
import { wipeBytes } from "../../secret/dispose.ts";
import { cosmosAddressFromCompressed } from "./address.ts";
import { COSMOS_HUB, cosmosPath, type CosmosChainConfig } from "./config.ts";

export interface CosmosDeriver extends ChainDeriver<DerivedAccount> {
  readonly config: CosmosChainConfig;
}

class CosmosDeriverImpl implements CosmosDeriver {
  readonly config: CosmosChainConfig;
  readonly #wallet: Wallet;

  constructor(wallet: Wallet, config: CosmosChainConfig) {
    this.#wallet = wallet;
    this.config = config;
  }

  derive(index: number): DerivedAccount {
    const i = assertU32Index(index, "index");
    return this.deriveAt(cosmosPath(this.config.coinType, i));
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
        address: cosmosAddressFromCompressed(pk, this.config.hrp),
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

/** Infallible. Default config is Cosmos Hub. */
export function createCosmosDeriver(
  wallet: Wallet,
  config: CosmosChainConfig = COSMOS_HUB,
): CosmosDeriver {
  return new CosmosDeriverImpl(wallet, config);
}
