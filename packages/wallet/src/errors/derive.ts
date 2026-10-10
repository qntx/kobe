/**
 * Unified HD / mnemonic / path / address-encoding failures.
 * Domain codes mirror kobe `DeriveError` partitions.
 */
export type DeriveErrorCode = "mnemonic" | "path" | "crypto" | "input" | "address_encoding";

export class DeriveError extends Error {
  override readonly name = "DeriveError";
  readonly code: DeriveErrorCode;

  constructor(code: DeriveErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.code = code;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export function isDeriveError(e: unknown): e is DeriveError {
  return e instanceof DeriveError;
}
