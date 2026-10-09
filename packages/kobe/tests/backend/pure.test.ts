import { describe, expect, test } from "vite-plus/test";

import { createPureBackend } from "../../src/backend/index.ts";
import { describeBackendConformance } from "./conformance.ts";

describeBackendConformance("pure", () => createPureBackend());

describe("createPureBackend specifics", () => {
  test("generateWallet with an injected zero rng gives abandon…about", async () => {
    const backend = createPureBackend({ rng: (bytes) => bytes.fill(0) });
    const wallet = await backend.generateWallet(12);
    await expect(backend.exportMnemonic(wallet)).resolves.toBe(
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    );
  });

  test("handles are scoped per backend instance", async () => {
    const a = createPureBackend();
    const b = createPureBackend();
    const walletA = await a.importMnemonic(
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    );
    const walletB = await b.importMnemonic(
      "legal winner thank year wave sausage worth useful legal winner thank yellow",
    );
    // Both backends issue handle 1 independently; releasing one leaves the
    // other's handle live.
    a.release(walletA);
    await expect(b.exportMnemonic(walletB)).resolves.toBe(
      "legal winner thank year wave sausage worth useful legal winner thank yellow",
    );
  });
});
