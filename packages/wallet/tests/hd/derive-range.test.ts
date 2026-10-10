import { expect, test } from "vitest";
import { assertU32Index, DeriveError, deriveRange, U32_MAX } from "../../src/hd/index.ts";

test("deriveRange maps inclusive start exclusive end", () => {
  expect(deriveRange(2, 3, (i) => i)).toEqual([2, 3, 4]);
});

test("deriveRange count 0 is empty", () => {
  expect(deriveRange(5, 0, (i) => i)).toEqual([]);
  expect(deriveRange(U32_MAX, 0, (i) => i)).toEqual([]);
});

test("reject non-integers, negatives, NaN, out of range", () => {
  for (const bad of [1.5, -1, Number.NaN, Number.POSITIVE_INFINITY, U32_MAX + 1]) {
    expect(() => assertU32Index(bad, "index")).toThrow(DeriveError);
    try {
      assertU32Index(bad, "index");
    } catch (e) {
      expect((e as DeriveError).code).toBe("input");
    }
  }
});

test("start + count overflow u32 throws input", () => {
  expect(() => deriveRange(U32_MAX, 1, (i) => i)).toThrow(DeriveError);
  try {
    deriveRange(U32_MAX - 1, 2, (i) => i);
  } catch (e) {
    expect((e as DeriveError).code).toBe("input");
  }
  expect(deriveRange(U32_MAX - 1, 1, (i) => i)).toEqual([U32_MAX - 1]);
});

test("deriveRange propagates callback errors", () => {
  expect(() =>
    deriveRange(0, 2, (i) => {
      if (i === 1) throw new DeriveError("path", "boom");
      return i;
    }),
  ).toThrow(DeriveError);
});
