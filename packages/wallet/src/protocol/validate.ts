/**
 * Strict validator combinators for the secret-area protocol. Both sides share them: the kernel
 * validates every request, the host validates every response. Anything that does not match is a
 * `ValidationError` — never a partially-accepted value.
 */
import type { NullValue } from "./index.ts";

export class ValidationError extends Error {
  override name = "ValidationError";
}

export type Validator<T> = (value: unknown) => T;

function fail(): never {
  throw new ValidationError();
}

export function literal<T extends NullValue | boolean | number | string>(
  expected: T,
): Validator<T> {
  return (value) => {
    if (value !== expected) {
      fail();
    }
    return expected;
  };
}

export const nullValue: Validator<NullValue> = literal(null);
export const bool: Validator<boolean> = (value) => {
  if (typeof value !== "boolean") {
    fail();
  }
  return value;
};

export function int(min: number, max: number): Validator<number> {
  return (value) => {
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < min || value > max) {
      fail();
    }
    return value;
  };
}

export function str(max: number, pattern?: RegExp): Validator<string> {
  return (value) => {
    if (
      typeof value !== "string" ||
      value.length > max ||
      (pattern !== undefined && !pattern.test(value))
    ) {
      fail();
    }
    return value;
  };
}

export function bytes(min: number, max?: number): Validator<Uint8Array> {
  const high = max ?? min;
  return (value) => {
    if (!(value instanceof Uint8Array) || value.length < min || value.length > high) {
      fail();
    }
    return value;
  };
}

export function arr<T>(item: Validator<T>, max: number, min = 0): Validator<ReadonlyArray<T>> {
  return (value) => {
    if (!Array.isArray(value) || value.length < min || value.length > max) {
      fail();
    }
    const out: T[] = [];
    for (const element of value) {
      out.push(item(element));
    }
    return out;
  };
}

class Opt<T> {
  readonly validator: Validator<T>;

  constructor(validator: Validator<T>) {
    this.validator = validator;
  }
}

export function opt<T>(validator: Validator<T>): Opt<T> {
  return new Opt(validator);
}

type Field = Validator<unknown> | Opt<unknown>;
type Shape = Record<string, Field>;

type RequiredKeys<S extends Shape> = {
  readonly [K in keyof S as S[K] extends Opt<unknown> ? never : K]: S[K] extends Validator<infer T>
    ? T
    : never;
};
type OptionalKeys<S extends Shape> = {
  readonly [K in keyof S as S[K] extends Opt<unknown> ? K : never]?: S[K] extends Opt<infer T>
    ? T
    : never;
};
type ShapeResult<S extends Shape> = RequiredKeys<S> & OptionalKeys<S>;

/** Exact key set: required keys present, optional keys allowed, nothing else. */
export function obj<S extends Shape>(shape: S): Validator<ShapeResult<S>> {
  const keys = Object.keys(shape);
  return (value) => {
    if (
      typeof value !== "object" ||
      value === null ||
      Array.isArray(value) ||
      value instanceof Uint8Array
    ) {
      fail();
    }
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- narrowed to a plain object above
    const record = value as Record<string, unknown>;
    for (const key of Object.keys(record)) {
      if (!Object.hasOwn(shape, key)) {
        fail();
      }
    }
    const out: Record<string, unknown> = {};
    for (const key of keys) {
      const field = shape[key];
      if (field === undefined) {
        fail();
      }
      const raw = record[key];
      if (field instanceof Opt) {
        if (raw !== undefined) {
          out[key] = field.validator(raw);
        }
      } else {
        if (!Object.hasOwn(record, key)) {
          fail();
        }
        out[key] = field(raw);
      }
    }
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the shape guarantees the keys
    return out as ShapeResult<S>;
  };
}

/** Tries each branch in order; the first match wins. */
export function union<Vs extends ReadonlyArray<Validator<unknown>>>(
  ...branches: Vs
): Validator<ReturnType<Vs[number]>> {
  return (value) => {
    for (const branch of branches) {
      try {
        // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- ReturnType of the branch union
        return branch(value) as ReturnType<Vs[number]>;
      } catch (error) {
        if (!(error instanceof ValidationError)) {
          throw error;
        }
      }
    }
    return fail();
  };
}

/** Validates a value and returns it, or undefined on a shape mismatch. */
export function validate<T>(validator: Validator<T>, value: unknown): T | undefined {
  try {
    return validator(value);
  } catch (error) {
    if (error instanceof ValidationError) {
      return undefined;
    }
    throw error;
  }
}
