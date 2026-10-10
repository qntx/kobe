/** Best-effort overwrite of a secret buffer (JS GC may retain copies). */
export function wipeBytes(buf: Uint8Array | undefined): void {
  if (buf) {
    buf.fill(0);
  }
}

/** Copy bytes into a new Uint8Array. */
export function copyBytes(src: Uint8Array): Uint8Array {
  return new Uint8Array(src);
}
