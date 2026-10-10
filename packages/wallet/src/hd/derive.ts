import { DeriveError } from "../errors/derive.ts";
import type { DerivedAccount } from "./account.ts";

export const U32_MAX = 0xff_ff_ff_ff;

export type ChainDeriver<A extends DerivedAccount = DerivedAccount> = {
  derive(index: number): A;
  deriveAt(path: string): A;
  deriveMany(start: number, count: number): A[];
};

/**
 * Accept only a JS number that is an integer in `[0, 0xffffffff]`.
 *
 * @throws DeriveError input
 */
export function assertU32Index(value: number, label: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > U32_MAX) {
    throw new DeriveError("input", `${label} must be an integer in [0, 0xffffffff]`);
  }
  return value;
}

/**
 * Batch helper: invoke `f` for each index in `[start, start + count)`. Overflow of `start + count`
 * as u32 → `DeriveError` `input`.
 *
 * @throws DeriveError input
 */
export function deriveRange<T>(start: number, count: number, f: (index: number) => T): T[] {
  const s = assertU32Index(start, "start");
  const c = assertU32Index(count, "count");
  if (s + c > U32_MAX) {
    throw new DeriveError("input", "derive_many: start + count overflows u32");
  }
  const out: T[] = [];
  const end = s + c;
  for (let i = s; i < end; i++) {
    out.push(f(i));
  }
  return out;
}
