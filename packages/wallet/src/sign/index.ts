/**
 * Signing public surface (`wallet/sign`).
 */
export { SignError, type SignErrorCode, isSignError } from "../errors/sign.ts";
export {
  secretKeyFromBytes,
  secretKeyFromDerived,
  secretKeyFromHex,
  type DerivedSecretSource,
  type SecretKey32,
} from "../secret/secret-key32.ts";
export { signerFromSecret } from "./from-secret.ts";
export { ed25519SignerFromSecret, type Ed25519Signer } from "./engines/ed25519.ts";
export { schnorrSignerFromSecret, type SchnorrSigner } from "./engines/schnorr.ts";
export { secp256k1SignerFromSecret, type Secp256k1Signer } from "./engines/secp256k1.ts";
export {
  EIP191_OFFSET,
  type SignOutput,
  signOutputPublicKey,
  signOutputToBytes,
  signOutputToHex,
  signOutputV,
  withVOffset,
} from "./output.ts";
export type {
  EncodeSignedTransaction,
  ExtractSignableBytes,
  SignDigest,
  SignMessage,
} from "./traits.ts";
