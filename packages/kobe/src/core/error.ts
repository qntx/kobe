/**
 * Error-code vocabulary shared with the Rust crates (`kobe_core::ErrorCode`).
 *
 * Every failure raised by this package is a {@link KobeError} carrying one of these codes; shared
 * vector error cases name the same strings.
 */
export type KobeErrorCode = "mnemonic" | "path" | "crypto" | "input" | "address-encoding";

/**
 * Unified HD / mnemonic / path / address-encoding failure.
 *
 * `code` partitions failures by domain, 1:1 with `kobe_core::DeriveError` variants:
 *
 * - `mnemonic` — a phrase failed to parse or validate (unknown word, bad checksum, word count,
 *   uppercase).
 * - `path` — a malformed derivation path.
 * - `crypto` — an underlying cryptographic primitive failed.
 * - `input` — caller-supplied input failed validation (entropy length, `generate` word count,
 *   account/index range, prefix expansion, use after `dispose`).
 * - `address-encoding` — bech32 / base58 / … encoding failure.
 */
export class KobeError extends Error {
  override readonly name = "KobeError";
  readonly code: KobeErrorCode;

  constructor(code: KobeErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.code = code;
  }
}
