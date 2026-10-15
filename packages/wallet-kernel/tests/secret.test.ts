import { describe, expect, it } from "vite-plus/test";

import { KernelError } from "../src/errors.ts";
import { Secret, wipe } from "../src/secret/secret.ts";
import { kernelError } from "./helpers.ts";

describe("Secret", () => {
  it("exposes bytes and length until wiped", () => {
    const secret = Secret.take(new Uint8Array([1, 2, 3]));
    expect(secret).toHaveLength(3);
    secret.use((bytes) => expect(bytes).toStrictEqual(new Uint8Array([1, 2, 3])));
    expect(secret.wiped).toBe(false);
    secret.wipe();
    expect(secret.wiped).toBe(true);
  });

  it("use and length after wipe throw integrity", () => {
    const secret = Secret.take(new Uint8Array([1]));
    secret.wipe();
    expect(kernelError(() => secret.use((b) => b.length))).toBe("integrity");
    expect(kernelError(() => secret.length)).toBe("integrity");
  });

  it("serialization throws", () => {
    const secret = Secret.take(new Uint8Array([1]));
    expect(() => JSON.stringify(secret)).toThrow(KernelError);
    expect(() => String(secret)).toThrow(KernelError);
    secret.wipe();
  });

  it("wipe() zeroes passed buffers", () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([4, 5]);
    wipe(a, b);
    expect(a).toStrictEqual(new Uint8Array(3));
    expect(b).toStrictEqual(new Uint8Array(2));
  });
});
