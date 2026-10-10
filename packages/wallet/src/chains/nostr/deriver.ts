import { assertU32Index, deriveRange, type ChainDeriver } from "../../hd/derive.ts";
import type { Wallet } from "../../hd/wallet.ts";
import { wipeBytes } from "../../secret/dispose.ts";
import { createNostrAccount, type NostrAccount } from "./account.ts";
import { encodeNpub, encodeNsec, nostrPath, xonlyFromCompressed } from "./nip19.ts";

export interface NostrDeriver extends ChainDeriver<NostrAccount> {}

class NostrDeriverImpl implements NostrDeriver {
  readonly #wallet: Wallet;

  constructor(wallet: Wallet) {
    this.#wallet = wallet;
  }

  derive(index: number): NostrAccount {
    return this.deriveAt(nostrPath(assertU32Index(index, "index")));
  }

  deriveAt(path: string): NostrAccount {
    const key = this.#wallet.deriveSecp256k1(path);
    const sk = key.privateKeyBytes();
    const compressed = key.compressedPublicKey();
    try {
      const xonly = xonlyFromCompressed(compressed);
      return createNostrAccount({
        path,
        privateKey: sk,
        xonlyPublicKey: xonly,
        npub: encodeNpub(xonly),
        nsec: encodeNsec(sk),
      });
    } finally {
      wipeBytes(sk);
      key.dispose();
    }
  }

  deriveMany(start: number, count: number): NostrAccount[] {
    return deriveRange(start, count, (i) => this.derive(i));
  }
}

export function createNostrDeriver(wallet: Wallet): NostrDeriver {
  return new NostrDeriverImpl(wallet);
}
