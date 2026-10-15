import type { WalletErrorCode } from "@qntx/wallet/types";

export type KernelErrorCode = WalletErrorCode;

/**
 * The only error type kernel code throws. Its code is the public `WalletErrorCode`: the kernel
 * returns it verbatim in the error payload. Messages are static strings: they must never echo user
 * input or secret contents.
 */
export class KernelError extends Error {
  readonly code: KernelErrorCode;
  readonly retryAt: number | undefined;
  /**
   * True when the error proves the stored vault itself is corrupt — the kernel latches the
   * corrupted state on it. Ordinary failures (a wrong factor, a bad param) leave it false.
   */
  readonly corrupted: boolean;

  constructor(code: KernelErrorCode, message: string, retryAt?: number, corrupted = false) {
    super(message);
    this.name = "KernelError";
    this.code = code;
    this.retryAt = retryAt;
    this.corrupted = corrupted;
  }
}
