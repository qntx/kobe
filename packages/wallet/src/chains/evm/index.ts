/**
 * EVM public surface (`wallet/evm`).
 */
export { evmAddressFromUncompressed, toEip55 } from "./address.ts";
export { createEvmDeriver, type EvmDeriver } from "./deriver.ts";
export { hashTypedDataJson } from "./eip712.ts";
export {
  concatEncoded,
  encodeBytes,
  encodeList,
  encodeSignedTypedTx,
  stripLeadingZeros,
} from "./rlp.ts";
export {
  createEvmSigner,
  EvmSigner,
  evmSignerFromBytes,
  evmSignerFromDerived,
  evmSignerFromHex,
  evmSignerFromSecretKey,
} from "./signer.ts";
export type { EvmSigner as EvmSignerApi } from "./signer.ts";
export { evmPath, type EvmDerivationStyle, parseEvmStyle } from "./style.ts";
