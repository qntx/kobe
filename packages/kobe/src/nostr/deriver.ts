import { wipeBytes } from "../core/bytes.ts";
import { assertU32Index, deriveRange } from "../core/derive.ts";
import type { Wallet } from "../core/wallet.ts";
import { createNostrAccount } from "./account.ts";
import type { NostrAccount } from "./account.ts";
import { encodeNpub, encodeNsec, nostrPath, xonlyFromCompressed } from "./nip19.ts";

/**
 * Nostr account deriver from a unified wallet — `kobe_nostr::Deriver` analog.
 *
 * Implements [NIP-06](https://nips.nostr.com/6): `index` maps to the hardened account level of the
 * BIP-32 path `m/44'/1237'/{index}'/0/0`.
 */
export class NostrDeriver {
  readonly #wallet: Wallet;

  constructor(wallet: Wallet) {
    this.#wallet = wallet;
  }

  /** @throws KobeError input (index range) | path | crypto | address-encoding */
  derive(index: number): NostrAccount {
    return this.deriveAt(nostrPath(assertU32Index(index, "index")));
  }

  /** @throws KobeError path | crypto | address-encoding | input if wallet is disposed */
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

  /** @throws KobeError input (range overflow) or any error from `derive` */
  deriveMany(start: number, count: number): NostrAccount[] {
    return deriveRange(start, count, (i) => this.derive(i));
  }
}
