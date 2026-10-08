import { describe, expect, test } from "vite-plus/test";

import { assertU32Index, deriveRange, U32_MAX } from "../../src/core/derive.ts";
import { KobeError } from "../../src/core/index.ts";

/** Run `f`, returning the thrown `KobeError.code`; sentinels keep assertions unconditional. */
function codeOf(f: () => unknown): string {
  try {
    f();
  } catch (error) {
    return error instanceof KobeError ? error.code : "<non-KobeError thrown>";
  }
  return "<no error thrown>";
}

const bombOnOne = (i: number): number => {
  if (i === 1) {
    throw new KobeError("path", "boom");
  }
  return i;
};

describe("deriveRange / assertU32Index", () => {
  test("deriveRange maps inclusive start exclusive end", () => {
    expect(deriveRange(2, 3, (i) => i)).toStrictEqual([2, 3, 4]);
  });

  test("deriveRange count 0 is empty", () => {
    expect(deriveRange(5, 0, (i) => i)).toStrictEqual([]);
    expect(deriveRange(U32_MAX, 0, (i) => i)).toStrictEqual([]);
  });

  test("rejects non-integers, negatives, NaN, out of range", () => {
    for (const bad of [1.5, -1, Number.NaN, Number.POSITIVE_INFINITY, U32_MAX + 1]) {
      expect(codeOf(() => assertU32Index(bad, "index"))).toBe("input");
    }
  });

  test("start + count overflow u32 throws input", () => {
    expect(codeOf(() => deriveRange(U32_MAX, 1, (i) => i))).toBe("input");
    expect(codeOf(() => deriveRange(U32_MAX - 1, 2, (i) => i))).toBe("input");
    expect(deriveRange(U32_MAX - 1, 1, (i) => i)).toStrictEqual([U32_MAX - 1]);
  });

  test("deriveRange propagates callback errors", () => {
    expect(() => deriveRange(0, 2, bombOnOne)).toThrow(KobeError);
  });
});
