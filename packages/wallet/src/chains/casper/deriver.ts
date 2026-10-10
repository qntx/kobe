import { assertU32Index, deriveRange, type ChainDeriver } from "../../hd/derive.ts";
import type { Wallet } from "../../hd/wallet.ts";
import { wipeBytes } from "../../secret/dispose.ts";
import { createCasperAccount, type CasperAccount } from "./account.ts";
import {
  casperAddressEd25519,
  casperAddressSecp256k1,
  ED25519_TAG,
  SECP256K1_TAG,
  taggedPublicKeyHex,
} from "./address.ts";
import { casperPath, type CasperKeyAlgo } from "./style.ts";

export interface CasperDeriver extends ChainDeriver<CasperAccount> {
  readonly algo: CasperKeyAlgo;
  deriveWith(algo: CasperKeyAlgo, index: number): CasperAccount;
  deriveManyWith(algo: CasperKeyAlgo, start: number, count: number): CasperAccount[];
  deriveAtWith(path: string, algo: CasperKeyAlgo): CasperAccount;
}

class CasperDeriverImpl implements CasperDeriver {
  readonly algo: CasperKeyAlgo;
  readonly #wallet: Wallet;

  constructor(wallet: Wallet, algo: CasperKeyAlgo) {
    this.#wallet = wallet;
    this.algo = algo;
  }

  derive(index: number): CasperAccount {
    return this.deriveWith(this.algo, index);
  }

  deriveWith(algo: CasperKeyAlgo, index: number): CasperAccount {
    return this.deriveAtWith(casperPath(algo, assertU32Index(index, "index")), algo);
  }

  deriveAt(path: string): CasperAccount {
    return this.deriveAtWith(path, this.algo);
  }

  deriveAtWith(path: string, algo: CasperKeyAlgo): CasperAccount {
    if (algo === "secp256k1") {
      const key = this.#wallet.deriveSecp256k1(path);
      const sk = key.privateKeyBytes();
      const pk = key.compressedPublicKey();
      try {
        return createCasperAccount({
          path,
          privateKey: sk,
          publicKey: { kind: "secp256k1-compressed", bytes: pk },
          address: casperAddressSecp256k1(pk),
          algo,
          taggedPublicKeyHex: taggedPublicKeyHex(SECP256K1_TAG, pk),
        });
      } finally {
        wipeBytes(sk);
        key.dispose();
      }
    }
    const key = this.#wallet.deriveEd25519(path);
    const sk = key.privateKeyBytes();
    const pk = key.publicKeyBytes();
    try {
      return createCasperAccount({
        path,
        privateKey: sk,
        publicKey: { kind: "ed25519", bytes: pk },
        address: casperAddressEd25519(pk),
        algo,
        taggedPublicKeyHex: taggedPublicKeyHex(ED25519_TAG, pk),
      });
    } finally {
      wipeBytes(sk);
      key.dispose();
    }
  }

  deriveMany(start: number, count: number): CasperAccount[] {
    return deriveRange(start, count, (i) => this.derive(i));
  }

  deriveManyWith(algo: CasperKeyAlgo, start: number, count: number): CasperAccount[] {
    return deriveRange(start, count, (i) => this.deriveWith(algo, i));
  }
}

/** Infallible. Default algorithm is secp256k1 (Ledger path). */
export function createCasperDeriver(
  wallet: Wallet,
  algo: CasperKeyAlgo = "secp256k1",
): CasperDeriver {
  return new CasperDeriverImpl(wallet, algo);
}
