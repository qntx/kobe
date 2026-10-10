/**
 * Credential persistence (`wallet/secret`).
 * SecretKey32 factories remain on `wallet/sign`.
 */
export {
  type CredentialBlob,
  type EncryptCredentialOptions,
  credentialFromBytes,
  credentialFromHex,
  credentialToBytes,
  credentialToHex,
  decryptBytes,
  decryptMnemonic,
  decryptSecret32,
  encryptBytes,
  encryptMnemonic,
  encryptSecret32,
} from "./credential.ts";
