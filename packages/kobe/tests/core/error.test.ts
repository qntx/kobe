import { describe, expect, test } from "vite-plus/test";

import { KobeError } from "../../src/core/index.ts";
import type { KobeErrorCode } from "../../src/core/index.ts";

describe("KobeError", () => {
  test("carries code, name and message", () => {
    const err = new KobeError("mnemonic", "checksum failed");
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(KobeError);
    expect(err.name).toBe("KobeError");
    expect(err.code).toBe("mnemonic");
    expect(err.message).toBe("checksum failed");
  });

  test("code vocabulary matches the Rust ErrorCode::as_str strings", () => {
    const codes: KobeErrorCode[] = ["mnemonic", "path", "crypto", "input", "address-encoding"];
    for (const code of codes) {
      expect(new KobeError(code, "x").code).toBe(code);
    }
  });
});
