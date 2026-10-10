/** Bitcoin public surface (`wallet/btc`). */
export { type BtcAccount, createBtcAccount } from "./account.ts";
export { btcAddressFromCompressed, encodeWif } from "./address.ts";
export { createBtcDeriver, type BtcDeriver } from "./deriver.ts";
export {
  BIP137_P2PKH_COMPRESSED,
  BIP137_P2PKH_UNCOMPRESSED,
  BIP137_SEGWIT_BECH32,
  BIP137_SEGWIT_P2SH,
  bitcoinMessageDigest,
  BtcSigner,
  type BtcMessageAddressType,
  type BtcSignerAddressSpec,
  taprootTweakSecret,
} from "./signer.ts";
export {
  btcPath,
  type BtcAddressType,
  type BtcNetwork,
  parseBtcAddressType,
  parseBtcNetwork,
} from "./types.ts";
