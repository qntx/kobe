import { expect, test } from "vitest";
import { DeriveError, isDeriveError } from "../src/hd/index.ts";
import { isSignError, SignError } from "../src/sign/index.ts";

test("DeriveError carries code and isDeriveError", () => {
  const err = new DeriveError("mnemonic", "checksum failed");
  expect(err).toBeInstanceOf(Error);
  expect(err).toBeInstanceOf(DeriveError);
  expect(err.name).toBe("DeriveError");
  expect(err.code).toBe("mnemonic");
  expect(err.message).toBe("checksum failed");
  expect(isDeriveError(err)).toBe(true);
  expect(isSignError(err)).toBe(false);
});

test("SignError carries code and isSignError", () => {
  const err = new SignError("invalid_key", "scalar out of range");
  expect(err).toBeInstanceOf(Error);
  expect(err).toBeInstanceOf(SignError);
  expect(err.name).toBe("SignError");
  expect(err.code).toBe("invalid_key");
  expect(isSignError(err)).toBe(true);
  expect(isDeriveError(err)).toBe(false);
});

test("type guards reject plain Error", () => {
  const err = new Error("nope");
  expect(isDeriveError(err)).toBe(false);
  expect(isSignError(err)).toBe(false);
});
