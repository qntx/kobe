/**
 * Aptos public surface (`wallet/aptos`).
 */
export { createAptosDeriver, type AptosDeriver } from "./deriver.ts";
export {
  aptosAddressFromPublicKey,
  aptosPath,
  aptosRawTxDomainHash,
  aptosTxSigningMessage,
} from "./hash.ts";
export {
  AptosSigner,
  aptosSignerFromBytes,
  aptosSignerFromDerived,
  aptosSignerFromHex,
  aptosSignerFromSecretKey,
  createAptosSigner,
} from "./signer.ts";
export type { AptosSigner as AptosSignerApi } from "./signer.ts";
