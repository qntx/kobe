/** EVM public surface (`wallet/evm`). */
export { evmAddressFromUncompressed, parseEvmAddress, toEip55 } from "./address.ts";
export { createEvmDeriver, type EvmDeriver } from "./deriver.ts";
export { hashTypedDataJson } from "./eip712.ts";
export {
  concatEncoded,
  encodeBytes,
  encodeList,
  encodeSignedLegacyTx,
  encodeSignedTypedTx,
  stripLeadingZeros,
} from "./rlp.ts";
export {
  authorizationHash,
  encodeSignature,
  EvmSigner,
  personalMessageHash,
  recoverAddress,
  transactionHash,
} from "./signer.ts";
export { evmPath, type EvmDerivationStyle, parseEvmStyle } from "./style.ts";
