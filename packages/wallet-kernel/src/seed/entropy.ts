import { KernelError } from "../errors.ts";
import type { Random } from "../platform.ts";

/** 12 words → 16 bytes, 24 words → 32 bytes of fresh entropy. */
export function randomEntropy(words: 12 | 24, random: Random): Uint8Array {
  const length = words === 12 ? 16 : 32;
  const entropy = random(length);
  if (entropy.length !== length) {
    throw new KernelError("integrity", "random source returned a wrong-length buffer");
  }
  return entropy;
}
