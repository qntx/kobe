import { readFileSync } from "node:fs";
import { join } from "node:path";

import { hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vite-plus/test";

import { isProtocolValue, kernelEvent, METHODS, responseError } from "../src/protocol/index.ts";
import type { ProtocolValue } from "../src/protocol/index.ts";

type Sample = {
  readonly name: string;
  readonly check: string;
  readonly message: unknown;
};
const vectors = JSON.parse(
  readFileSync(join(import.meta.dirname, "../../../vectors/protocol.json"), "utf8"),
) as { accept: Sample[]; reject: Sample[] };

/**
 * Turns `{ "$bytes": "<hex>" }` markers back into Uint8Array so a JSON sample exercises the same
 * values a structured-clone request carries.
 */
function decodeBytes(value: unknown): unknown {
  if (typeof value !== "object" || value === null) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(decodeBytes);
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length === 1 && keys[0] === "$bytes" && typeof record["$bytes"] === "string") {
    return hexToBytes(record["$bytes"]);
  }
  const out: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(record)) {
    out[key] = decodeBytes(child);
  }
  return out;
}

const REQUEST_KEYS = new Set(["v", "id", "method", "session", "params"]);

/**
 * The kernel's request-envelope rules (kernel.ts `respond`), spelled out on the host side: both
 * peers must agree on which raw messages reach method dispatch.
 */
function checkRequest(message: unknown): void {
  if (typeof message !== "object" || message === null || Array.isArray(message)) {
    throw new Error("malformed request");
  }
  if (Object.getPrototypeOf(message) !== Object.prototype) {
    throw new Error("malformed request");
  }
  const request = message as Record<string, unknown>;
  if (request["v"] !== 1) {
    throw new Error("protocol version mismatch");
  }
  const { id, method, session } = request;
  if (typeof id !== "number" || !Number.isSafeInteger(id) || id < 0) {
    throw new Error("malformed request id");
  }
  for (const key of Object.keys(request)) {
    if (!REQUEST_KEYS.has(key)) {
      throw new Error("unexpected request field");
    }
  }
  if (session !== undefined && (typeof session !== "string" || session.length > 64)) {
    throw new Error("malformed session field");
  }
  if (typeof method !== "string" || !Object.hasOwn(METHODS, method)) {
    throw new Error("unknown method");
  }
  if (!("params" in request)) {
    throw new Error("missing params");
  }
  const { params } = request;
  if (!isProtocolValue(params)) {
    throw new Error("malformed params");
  }
  const spec = METHODS[method as keyof typeof METHODS];
  spec.params(params);
}

/** Runs the sample's named contract against the `$bytes`-decoded message. */
function check(sample: Sample): void {
  const message = decodeBytes(sample.message);
  if (sample.check === "request") {
    checkRequest(message);
    return;
  }
  if (sample.check === "event") {
    kernelEvent(message);
    return;
  }
  if (sample.check === "responseError") {
    const { err } = message as { err?: unknown };
    responseError(err);
    return;
  }
  if (sample.check.startsWith("response:")) {
    const method = sample.check.slice("response:".length) as keyof typeof METHODS;
    const { ok } = message as { ok: ProtocolValue };
    METHODS[method].result(ok);
    return;
  }
  throw new Error(`unknown check: ${sample.check}`);
}

describe("protocol vectors", () => {
  it.each(vectors.accept)("accepts $name", (sample) => {
    expect(() => check(sample)).not.toThrow();
  });

  it.each(vectors.reject)("rejects $name", (sample) => {
    let threw = false;
    try {
      check(sample);
    } catch {
      threw = true;
    }
    expect(threw).toBe(true);
  });
});
