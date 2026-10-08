/**
 * Bundle entry for the Hermes smoke test: import the package entry as a namespace and verify it
 * evaluates to a module namespace object on Hermes.
 */
import * as index from "../../src/index.ts";

declare function print(msg: string): void;
declare function quit(code: number): void;

try {
  if (typeof index !== "object" || index === null) {
    throw new Error("package entry is not a module namespace object");
  }
  print("HERMES_SMOKE_OK");
} catch (error) {
  print(
    `HERMES_SMOKE_FAIL: ${error instanceof Error ? (error.stack ?? error.message) : String(error)}`,
  );
  quit(1);
}
