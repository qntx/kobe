import { describe, expect, it } from "vite-plus/test";

import { METHODS } from "@qntx/wallet/protocol";

import { createHarness, mulberry32 } from "./harness.ts";

const METHOD_NAMES = Object.keys(METHODS);

function randomMalformed(next: () => number): unknown {
  const pick = (n: number) => Math.floor(next() * n);
  // Every generator below produces a structurally invalid request part.
  const malformedScalar = (): unknown => {
    switch (pick(6)) {
      case 0:
        return "not-a-valid-shape";
      case 1:
        return -1.5;
      case 2:
        return { unexpected: true };
      case 3:
        return [1, 2, 3];
      case 4:
        return "x".repeat(3000);
      default:
        return false;
    }
  };

  let method =
    pick(10) === 0 ? "no.such.method" : (METHOD_NAMES[pick(METHOD_NAMES.length)] ?? "status");
  // These three methods accept `params: null` — keep them malformed by construction.
  const nullParamMethods = new Set(["status", "vault.reset", "nostr.createNip46ClientKey"]);
  const style = pick(8);
  if (nullParamMethods.has(method) && (style === 4 || style === 5 || style === 7)) {
    method = "vault.unlock"; // a method whose null params are malformed
  }

  switch (style) {
    case 0:
      return malformedScalar(); // not even an object
    case 1:
      return { v: pick(2) + 2, id: pick(100), method, params: null }; // bad version
    case 2:
      return { v: 1, id: "nope", method, params: null }; // bad id type
    case 3:
      return { v: 1, id: pick(100), method, params: malformedScalar() };
    case 4:
      return { v: 1, id: pick(100), method, params: null, extra: "field" };
    case 5:
      return { v: 1, id: pick(100), method }; // missing params
    case 6:
      return { v: 1, id: pick(100), method, params: { factor: malformedScalar() } };
    default:
      return { v: 1, id: pick(100), method: "no.such.method", params: null };
  }
}

describe("protocol fuzz", () => {
  it(
    "malformed requests yield integrity errors and the kernel keeps serving",
    { timeout: 60000 },
    async () => {
      const h = createHarness({ seed: 7 });
      await h.settle();
      const next = mulberry32(0xdeadbeef);
      let checked = 0;
      for (let i = 0; i < 3000; i++) {
        const malformed = randomMalformed(next);
        // oxlint-disable-next-line eslint/no-await-in-loop -- requests are dispatched sequentially
        const response = await h.sendRaw(malformed);
        expect(response).toHaveProperty("err.code", "integrity");
        checked++;
      }
      expect(checked).toBe(3000);
      // Still serving: a well-formed request works after the fuzz barrage.
      const res = await h.call("status");
      expect("ok" in res).toBe(true);
    },
  );
});
