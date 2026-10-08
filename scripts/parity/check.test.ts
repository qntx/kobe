import { describe, expect, test } from "vite-plus/test";

import { checkParity } from "./check.ts";

const TRUE = (): boolean => true;
const EMPTY = (): string => "";
const mapReader =
  (files: Map<string, string>) =>
  (p: string): string =>
    files.get(p) ?? "";

function cap(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "core.example",
    tier: "B",
    status: "ts-only",
    milestone: "NK1",
    ts: { module: "src/x.ts", tests: ["tests/x.test.ts"] },
    rust: null,
    vectors: [],
    ...overrides,
  };
}

function parity(caps: Array<Record<string, unknown>>): unknown {
  return { schema: 1, capabilities: caps };
}

describe("parity check", () => {
  test("accepts a minimal valid document", () => {
    expect(checkParity(parity([cap()]), [], TRUE, EMPTY)).toStrictEqual([]);
  });

  test("rejects duplicate ids", () => {
    const errors = checkParity(parity([cap(), cap()]), [], TRUE, EMPTY);
    expect(errors).toStrictEqual(['capability "core.example": duplicate id']);
  });

  test("rejects an invalid tier", () => {
    const errors = checkParity(parity([cap({ tier: "D" })]), [], TRUE, EMPTY);
    expect(errors).toStrictEqual(['capability "core.example": tier must be one of A|B|C']);
  });

  test("rejects n/a outside tier C", () => {
    const errors = checkParity(parity([cap({ status: "n/a" })]), [], TRUE, EMPTY);
    expect(errors).toStrictEqual([
      'capability "core.example": status "n/a" is only allowed for tier C',
    ]);
  });

  test("requires tier C to be n/a", () => {
    const errors = checkParity(parity([cap({ tier: "C" })]), [], TRUE, EMPTY);
    expect(errors).toStrictEqual(['capability "core.example": tier C must have status "n/a"']);
  });

  test("rejects missing referenced paths", () => {
    const errors = checkParity(parity([cap()]), [], () => false, EMPTY);
    expect(errors).toStrictEqual([
      'capability "core.example": referenced path does not exist: src/x.ts',
      'capability "core.example": referenced path does not exist: tests/x.test.ts',
    ]);
  });

  test("rejects stable without tests on both sides", () => {
    const errors = checkParity(
      parity([cap({ status: "stable", rust: { module: null, tests: [] } })]),
      [],
      TRUE,
      EMPTY,
    );
    expect(errors).toStrictEqual([
      'capability "core.example": "stable" requires non-empty ts.tests and rust.tests',
    ]);
  });

  test("requires a vector for stable tier A", () => {
    const errors = checkParity(
      parity([cap({ tier: "A", status: "stable", rust: { module: null, tests: ["rust/x.rs"] } })]),
      [],
      TRUE,
      EMPTY,
    );
    expect(errors).toStrictEqual([
      'capability "core.example": tier A "stable" requires at least one vector file',
    ]);
  });

  test("rejects unreferenced vector files", () => {
    const errors = checkParity(parity([cap()]), ["vectors/core/orphan.json"], TRUE, EMPTY);
    expect(errors).toStrictEqual([
      "vector file is not referenced by any capability: vectors/core/orphan.json",
    ]);
  });

  test("requires each vector to be cited in a test file", () => {
    const c = cap({ vectors: ["vectors/core/x.json"] });
    const files = new Map([
      ["src/x.ts", ""],
      ["tests/x.test.ts", "reads nothing relevant"],
      ["vectors/core/x.json", "{}"],
    ]);
    const errors = checkParity(
      parity([c]),
      ["vectors/core/x.json"],
      (p) => files.has(p),
      mapReader(files),
    );
    expect(errors).toStrictEqual([
      'capability "core.example": vector vectors/core/x.json is not referenced by any of its test files',
    ]);
  });

  test("accepts a vector cited by test file contents", () => {
    const c = cap({ vectors: ["vectors/core/x.json"] });
    const files = new Map([
      ["src/x.ts", ""],
      ["tests/x.test.ts", 'readFileSync("vectors/core/x.json")'],
      ["vectors/core/x.json", "{}"],
    ]);
    const errors = checkParity(
      parity([c]),
      ["vectors/core/x.json"],
      (p) => files.has(p),
      mapReader(files),
    );
    expect(errors).toStrictEqual([]);
  });
});
