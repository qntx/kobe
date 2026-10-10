/**
 * Compact recoverable ECDSA signature: `r || s` plus the raw recovery parity.
 *
 * `recovery` is always `0` or `1` — chain wire formats that add an offset (EIP-191/712 `27`,
 * BIP-137 header bytes) encode it in the chain module, never here.
 */
export type RecoverableSignature = {
  /** `r || s` (64 bytes). */
  readonly signature: Uint8Array;
  /** Recovery parity; always `0` or `1`. */
  readonly recovery: 0 | 1;
};
