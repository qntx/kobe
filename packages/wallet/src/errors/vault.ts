/** Unified vault / KDF failures. Domain codes mirror kobe `VaultError` partitions. */
export type VaultErrorCode = "input" | "crypto" | "decrypt" | "version";

export class VaultError extends Error {
  override readonly name = "VaultError";
  readonly code: VaultErrorCode;

  constructor(code: VaultErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.code = code;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export function isVaultError(e: unknown): e is VaultError {
  return e instanceof VaultError;
}
