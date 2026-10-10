import type { SignOutput } from "./output.ts";

export interface SignDigest {
  /** @throws SignError; digest length must be 32 */
  signDigest(digest: Uint8Array): SignOutput;
}

export interface SignMessage {
  /** @throws SignError */
  signMessage(message: Uint8Array): SignOutput;
}

export interface EncodeSignedTransaction {
  encodeSignedTransaction(unsignedTx: Uint8Array, signature: SignOutput): Uint8Array;
}

export interface ExtractSignableBytes {
  /**
   * View (subarray) into `txBytes`, valid while `txBytes` is alive.
   * @throws SignError invalid_transaction
   */
  extractSignableBytes(txBytes: Uint8Array): Uint8Array;
}
