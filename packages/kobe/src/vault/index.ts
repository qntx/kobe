export { VAULT_VERSION, open, seal } from "./envelope.ts";
export { PASSWORD_ITERATIONS, derivePasswordKey, derivePrfKey } from "./kdf.ts";
export type { Pbkdf2Sha256 } from "./kdf.ts";
export { passkeyWallet } from "./passkey.ts";
