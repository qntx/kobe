/** Vault public surface (`wallet/vault`). */
export { isVaultError, VaultError, type VaultErrorCode } from "../errors/vault.ts";
export { open, seal, VAULT_VERSION } from "./envelope.ts";
export { derivePasswordKey, derivePrfKey, PASSWORD_ITERATIONS, type Pbkdf2Sha256 } from "./kdf.ts";
export { passkeyWallet } from "./passkey.ts";
