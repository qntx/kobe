/**
 * Bundle entry for the Hermes smoke test: import both package entries and run a BIP-39 / NIP-06
 * known-answer check on Hermes.
 */
import { Wallet } from "../../src/core/index.ts";
import { NostrDeriver } from "../../src/nostr/index.ts";

declare function print(msg: string): void;
declare function quit(code: number): void;

// NIP-06 test vector 1, account 0.
const TV1_MNEMONIC =
  "leader monkey parrot ring guide accident before fence cannon height naive bean";
const TV1_NPUB = "npub1zutzeysacnf9rru6zqwmxd54mud0k44tst6l70ja5mhv8jjumytsd2x7nu";
const ABANDON =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

try {
  const wallet = Wallet.fromEntropy(new Uint8Array(16));
  if (wallet.mnemonic() !== ABANDON) {
    throw new Error("fromEntropy mnemonic mismatch");
  }
  const tv1 = Wallet.fromMnemonic(TV1_MNEMONIC);
  const account = new NostrDeriver(tv1).derive(0);
  if (account.npub() !== TV1_NPUB) {
    throw new Error("NIP-06 npub mismatch");
  }
  print("HERMES_SMOKE_OK");
} catch (error) {
  print(
    `HERMES_SMOKE_FAIL: ${error instanceof Error ? (error.stack ?? error.message) : String(error)}`,
  );
  quit(1);
}
