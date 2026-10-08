import { KobeError } from "./error.ts";

export const U32_MAX = 0xff_ff_ff_ff;

/**
 * Accept only a JS number that is an integer in `[0, 0xffffffff]`.
 *
 * @throws KobeError input
 */
export function assertU32Index(value: number, label: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > U32_MAX) {
    throw new KobeError("input", `${label} must be an integer in [0, 0xffffffff]`);
  }
  return value;
}

/**
 * Batch helper: invoke `f` for each index in `[start, start + count)`. Overflow of `start + count`
 * as u32 → `KobeError` `input`.
 *
 * @throws KobeError input
 */
export function deriveRange<T>(start: number, count: number, f: (index: number) => T): T[] {
  const s = assertU32Index(start, "start");
  const c = assertU32Index(count, "count");
  if (s + c > U32_MAX) {
    throw new KobeError("input", "derive_many: start + count overflows u32");
  }
  const out: T[] = [];
  const end = s + c;
  for (let i = s; i < end; i++) {
    out.push(f(i));
  }
  return out;
}
