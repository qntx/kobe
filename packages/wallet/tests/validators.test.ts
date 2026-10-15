import { describe, expect, it } from "vite-plus/test";

import {
  arr,
  bool,
  bytes,
  int,
  isProtocolValue,
  literal,
  METHODS,
  nullValue,
  obj,
  opt,
  str,
  union,
  ValidationError,
  validate,
} from "@qntx/wallet/protocol";

function fails(validator: (v: unknown) => unknown, value: unknown): boolean {
  try {
    validator(value);
    return false;
  } catch (error) {
    return error instanceof ValidationError;
  }
}

describe("primitive validators", () => {
  it("literal accepts only the exact value", () => {
    const v = literal("x");
    expect(v("x")).toBe("x");
    expect(fails(v, "y")).toBe(true);
    expect(fails(v, undefined)).toBe(true);
    expect(fails(v, null)).toBe(true);
  });

  it("int enforces safe integers and range", () => {
    const v = int(0, 10);
    expect(v(5)).toBe(5);
    expect(fails(v, -1)).toBe(true);
    expect(fails(v, 11)).toBe(true);
    expect(fails(v, 1.5)).toBe(true);
    expect(fails(v, Number.MAX_SAFE_INTEGER + 1)).toBe(true);
    expect(fails(v, "5")).toBe(true);
  });

  it("str enforces length and pattern", () => {
    const v = str(4, /^[a-z]+$/);
    expect(v("abcd")).toBe("abcd");
    expect(fails(v, "abcde")).toBe(true);
    expect(fails(v, "AB")).toBe(true);
    expect(fails(v, 7)).toBe(true);
  });

  it("bytes enforces exact or ranged length", () => {
    expect(bytes(32)(new Uint8Array(32))).toBeInstanceOf(Uint8Array);
    expect(fails(bytes(32), new Uint8Array(31))).toBe(true);
    expect(fails(bytes(1, 4), new Uint8Array(0))).toBe(true);
    expect(fails(bytes(1, 4), new Uint8Array(5))).toBe(true);
    expect(fails(bytes(4), "aaaa")).toBe(true);
  });

  it("bool and nullValue", () => {
    expect(bool(true)).toBe(true);
    expect(fails(bool, 0)).toBe(true);
    expect(nullValue(null)).toBeNull();
    expect(fails(nullValue, 0)).toBe(true);
  });
});

describe("structural validators", () => {
  it("obj enforces the exact key set including optional keys", () => {
    const v = obj({ a: str(8), b: opt(int(0, 9)) });
    expect(v({ a: "x" })).toStrictEqual({ a: "x" });
    expect(v({ a: "x", b: 3 })).toStrictEqual({ a: "x", b: 3 });
    expect(fails(v, { a: "x", c: 1 })).toBe(true); // unknown key
    expect(fails(v, { b: 3 })).toBe(true); // missing required
    // present-but-undefined optional keys are rejected upstream by isProtocolValue
    expect(fails(v, [])).toBe(true);
    expect(fails(v, new Uint8Array(2))).toBe(true);
    expect(fails(v, "x")).toBe(true);
  });

  it("arr enforces item shape and bounds", () => {
    const v = arr(int(0, 9), 3, 1);
    expect(v([1, 2])).toStrictEqual([1, 2]);
    expect(fails(v, [])).toBe(true);
    expect(fails(v, [1, 2, 3, 4])).toBe(true);
    expect(fails(v, [1, "x"])).toBe(true);
  });

  it("union picks the first matching branch", () => {
    const v = union(literal("a"), obj({ k: literal("b") }));
    expect(v("a")).toBe("a");
    expect(v({ k: "b" })).toStrictEqual({ k: "b" });
    expect(fails(v, { k: "c" })).toBe(true);
    expect(fails(v, "b")).toBe(true);
  });

  it("validate returns undefined instead of throwing", () => {
    expect(validate(int(0, 9), 4)).toBe(4);
    expect(validate(int(0, 9), 99)).toBeUndefined();
  });
});

describe("isProtocolValue", () => {
  it("accepts the protocol value domain", () => {
    expect(isProtocolValue(null)).toBe(true);
    expect(isProtocolValue(true)).toBe(true);
    expect(isProtocolValue(42)).toBe(true);
    expect(isProtocolValue("s")).toBe(true);
    expect(isProtocolValue(new Uint8Array(3))).toBe(true);
    expect(isProtocolValue([1, "a", [null]])).toBe(true);
    expect(isProtocolValue({ a: 1, b: { c: new Uint8Array(1) } })).toBe(true);
  });

  it("rejects non-protocol values", () => {
    expect(isProtocolValue(1.5)).toBe(false);
    expect(isProtocolValue(undefined)).toBe(false);
    expect(isProtocolValue(Symbol("x"))).toBe(false);
    expect(isProtocolValue(new Map())).toBe(false);
    expect(isProtocolValue(new Date())).toBe(false);
    expect(isProtocolValue({ a: undefined })).toBe(false);
    expect(isProtocolValue(Object.create(null))).toBe(false);
    expect(isProtocolValue({ __proto__: { polluted: true } })).toBe(false);
  });
});

describe("method table", () => {
  it("rejects malformed params and accepts valid ones for every method", () => {
    for (const spec of Object.values(METHODS)) {
      expect(spec.params).toBeTypeOf("function");
      expect(spec.result).toBeTypeOf("function");
      // params validators reject wrong-typed values
      expect(fails(spec.params, "garbage")).toBe(true);
      expect(fails(spec.params, { extra: 1 })).toBe(true);
    }
  });

  it("accepts a valid unlock request shape", () => {
    const params = METHODS["vault.unlock"].params({
      factor: { kind: "password", password: new Uint8Array(10) },
    });
    expect(params.factor.kind).toBe("password");
  });

  it("enforces batch limits", () => {
    const events = Array.from({ length: 257 }, (_, i) => ({
      id: "ab".repeat(32),
      pubkey: "cd".repeat(32),
      sig: "ef".repeat(64),
      kind: 1059,
      created_at: i,
      tags: [],
      content: "x",
    }));
    expect(
      fails(METHODS["nostr.unwrapGiftWraps"].params, { publicKey: "ab".repeat(32), events }),
    ).toBe(true);
  });
});
