import type { SignOutput } from "./output.ts";

export type SignDigest = {
  /** @throws SignError; digest length must be 32 */
  signDigest(digest: Uint8Array): SignOutput;
};

export type SignMessage = {
  /** @throws SignError */
  signMessage(message: Uint8Array): SignOutput;
};

export type EncodeSignedTransaction = {
  encodeSignedTransaction(unsignedTx: Uint8Array, signature: SignOutput): Uint8Array;
};

export type ExtractSignableBytes = {
  /**
   * View (subarray) into `txBytes`, valid while `txBytes` is alive.
   *
   * @throws SignError invalid_transaction
   */
  extractSignableBytes(txBytes: Uint8Array): Uint8Array;
};
