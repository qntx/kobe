/**
 * EVM derivation and signing (`@qntx/kobe/evm`) — `kobe-evm` analog.
 *
 * BIP-44 derivation to EIP-55 addresses plus signing for transactions (legacy EIP-155, EIP-2930,
 * EIP-1559, EIP-7702), EIP-191 personal messages, EIP-712 v4 typed data and EIP-7702
 * authorizations. Signers hash the full payload themselves; digests, encoders, address parsing and
 * recovery are pure functions.
 */
export { parseAddress, toChecksum } from "./address.ts";
export { EvmDeriver } from "./deriver.ts";
export {
  authorizationHash,
  encodeSignature,
  encodeSignedTransaction,
  EvmSigner,
  personalMessageHash,
  recoverAddress,
  transactionHash,
  typedDataHash,
} from "./signer.ts";
export { type EvmDerivationStyle, evmPath } from "./style.ts";
