import { KernelError } from "../errors.ts";

/** Overwrites buffers with zeros. The only "zeroing" we can rely on. */
export function wipe(...buffers: Uint8Array[]): void {
  for (const buffer of buffers) {
    buffer.fill(0);
  }
}

/**
 * Fatal UTF-8 decode of a single-use secret input (passwords, nsec bytes, mnemonics): the input
 * buffer is wiped in every case, and invalid UTF-8 fails closed. Callers that still need the bytes
 * afterwards must decode without wiping — see `decodePassword` in the vault layer.
 */
export function decodeUtf8Secret(bytes: Uint8Array): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new KernelError("invalid-input", "input is not valid UTF-8");
  } finally {
    wipe(bytes);
  }
}

/**
 * Opaque holder for long-lived secrets (DEK, pending entropy). The bytes are reachable only inside
 * `use`; serialization and stringification throw so a secret cannot leak into logs or the wire by
 * accident.
 */
export class Secret {
  #bytes: Uint8Array | undefined;

  private constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
  }

  /** Takes ownership of `bytes` without copying; the caller must not reuse it. */
  static take(bytes: Uint8Array): Secret {
    return new Secret(bytes);
  }

  get length(): number {
    const bytes = this.#bytes;
    if (bytes === undefined) {
      throw new KernelError("integrity", "secret already wiped");
    }
    return bytes.length;
  }

  get wiped(): boolean {
    return this.#bytes === undefined;
  }

  use<T>(fn: (bytes: Uint8Array) => T): T {
    const bytes = this.#bytes;
    if (bytes === undefined) {
      throw new KernelError("integrity", "secret already wiped");
    }
    return fn(bytes);
  }

  wipe(): void {
    const bytes = this.#bytes;
    if (bytes !== undefined) {
      bytes.fill(0);
      this.#bytes = undefined;
    }
  }

  toJSON(): never {
    throw new KernelError("integrity", "secret is not serializable");
  }

  toString(): never {
    throw new KernelError("integrity", "secret is not a string");
  }
}
