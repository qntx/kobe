/**
 * Bundle entry for the Hermes smoke test. The globals module MUST evaluate before any kernel module
 * (kernel sources construct `new TextDecoder()` at call sites and noble reads `crypto` lazily — but
 * shim ordering must still precede first use), so `smoke.ts` is imported dynamically: import
 * sorting would otherwise hoist the static kernel imports of a statically-linked smoke module ahead
 * of the shim installation.
 */
import { hermesGlobalsInstalled, missingGlobals, shimmedGlobals } from "./globals.ts";

declare function print(msg: string): void;
declare function quit(code: number): void;

async function bootstrap(): Promise<void> {
  if (!hermesGlobalsInstalled) {
    throw new Error("smoke: globals module not evaluated");
  }
  print(`HERMES_GLOBALS_MISSING: ${missingGlobals.join(",")}`);
  print(`HERMES_GLOBALS_SHIMMED: ${shimmedGlobals.join(",")}`);
  const { main } = await import("./smoke.ts");
  await main();
}

// oxlint-disable-next-line unicorn/prefer-top-level-await -- top-level await cannot appear in the iife classic-script bundle Hermes runs
void (async (): Promise<void> => {
  try {
    await bootstrap();
    print("HERMES_SMOKE_OK");
  } catch (error) {
    print(
      `HERMES_SMOKE_FAIL: ${error instanceof Error ? (error.stack ?? error.message) : String(error)}`,
    );
    quit(1);
  }
})();
