import { HDKey } from "@scure/bip32";

/** BIP-32 master key. The caller owns it and must `wipePrivateData()`. */
export function masterKey(seed: Uint8Array): HDKey {
  return HDKey.fromMasterSeed(seed);
}
