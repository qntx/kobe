/**
 * Unified signing / key-parse / wire failures.
 * Domain codes mirror signer `SignError` partitions.
 */
export type SignErrorCode =
  | "invalid_key"
  | "invalid_message"
  | "signing_failed"
  | "invalid_signature"
  | "invalid_transaction";

export class SignError extends Error {
  override readonly name = "SignError";
  readonly code: SignErrorCode;

  constructor(code: SignErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.code = code;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export function isSignError(e: unknown): e is SignError {
  return e instanceof SignError;
}
