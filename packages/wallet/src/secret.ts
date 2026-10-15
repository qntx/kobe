import { WalletError } from "./types.ts";
import type { ExportedSecret } from "./types.ts";

/**
 * One-shot secret bytes handed to the app: `read` returns them exactly once, `wipe` zeroes them.
 * The second `read` fails closed.
 */
export class SingleUseSecret implements ExportedSecret {
  private bytes: Uint8Array | undefined;

  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
  }

  read(): Uint8Array {
    const { bytes } = this;
    if (bytes === undefined) {
      throw new WalletError("invalid-input", "secret already read or wiped");
    }
    this.bytes = undefined;
    return bytes;
  }

  wipe(): void {
    this.bytes?.fill(0);
    this.bytes = undefined;
  }
}
