import { DeriveError } from "../../errors/derive.ts";
import { assertU32Index, deriveRange, type ChainDeriver } from "../../hd/derive.ts";
import type { Wallet } from "../../hd/wallet.ts";
import { wipeBytes } from "../../secret/dispose.ts";
import { btcAddressFromCompressed, encodeWif } from "./address.ts";
import { createBtcAccount, type BtcAccount } from "./account.ts";
import { addressTypeFromPurpose, btcPath, type BtcAddressType, type BtcNetwork } from "./types.ts";

export interface BtcDeriver extends ChainDeriver<BtcAccount> {
  readonly network: BtcNetwork;
  deriveWith(addressType: BtcAddressType, index: number): BtcAccount;
  deriveManyWith(addressType: BtcAddressType, start: number, count: number): BtcAccount[];
  deriveAtWith(path: string, addressType: BtcAddressType): BtcAccount;
}

function inferType(path: string): BtcAddressType {
  const first = path.trim().split("/")[1];
  if (!first) {
    throw new DeriveError("path", `btc: cannot infer address type from path '${path}'`);
  }
  const hardened = first.endsWith("'") || first.endsWith("h") || first.endsWith("H");
  const n = Number(hardened ? first.slice(0, -1) : first);
  const type = hardened ? addressTypeFromPurpose(n) : undefined;
  if (!type) {
    throw new DeriveError(
      "path",
      `btc: cannot infer address type from path '${path}'; purpose must be 44'/49'/84'/86'`,
    );
  }
  return type;
}

class BtcDeriverImpl implements BtcDeriver {
  readonly network: BtcNetwork;
  readonly #wallet: Wallet;

  constructor(wallet: Wallet, network: BtcNetwork) {
    this.#wallet = wallet;
    this.network = network;
  }

  derive(index: number): BtcAccount {
    return this.deriveWith("p2wpkh", index);
  }

  deriveWith(addressType: BtcAddressType, index: number): BtcAccount {
    const i = assertU32Index(index, "index");
    return this.deriveAtWith(btcPath(addressType, this.network, i), addressType);
  }

  deriveAt(path: string): BtcAccount {
    return this.deriveAtWith(path, inferType(path));
  }

  deriveAtWith(path: string, addressType: BtcAddressType): BtcAccount {
    const key = this.#wallet.deriveSecp256k1(path);
    const sk = key.privateKeyBytes();
    const pk = key.compressedPublicKey();
    try {
      return createBtcAccount({
        path,
        privateKey: sk,
        publicKey: pk,
        address: btcAddressFromCompressed(pk, this.network, addressType),
        wif: encodeWif(sk, this.network),
        addressType,
      });
    } finally {
      wipeBytes(sk);
      key.dispose();
    }
  }

  deriveMany(start: number, count: number): BtcAccount[] {
    return deriveRange(start, count, (i) => this.derive(i));
  }

  deriveManyWith(addressType: BtcAddressType, start: number, count: number): BtcAccount[] {
    return deriveRange(start, count, (i) => this.deriveWith(addressType, i));
  }
}

/** Infallible. Holds a live Wallet reference; does not copy seed. */
export function createBtcDeriver(wallet: Wallet, network: BtcNetwork = "mainnet"): BtcDeriver {
  return new BtcDeriverImpl(wallet, network);
}
