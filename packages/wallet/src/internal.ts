import type { Factor, MethodName, ParamsOf, ResultOf } from "./protocol/index.ts";
/**
 * Channel internals shared between the core Wallet and the protocol subpath modules
 * (@qntx/wallet/nostr, later spark/chains). This file is NOT a package subpath — modules look a
 * Wallet up in the WeakMap, so a foreign object has no channel to reach.
 */
import { WalletError } from "./types.ts";
import type { InitialFactor, UnlockFactor, Wallet, WalletSnapshot } from "./types.ts";

export type WalletInternals = {
  /** One validated request on the kernel channel (awaits the live port's first status). */
  readonly call: <M extends MethodName>(
    method: M,
    params: ParamsOf<M>,
    transfer?: ArrayBuffer[],
  ) => Promise<ResultOf<M>>;
  /** The live kernel port's first-status gate — re-read per call (a respawn replaces it). */
  readonly ready: () => Promise<void>;
  readonly snapshot: () => WalletSnapshot;
  /** Marks a user verification in flight on the snapshot (`verifying`). */
  readonly withVerifying: <T>(fn: () => Promise<T>) => Promise<T>;
  /** Public UnlockFactor → wire factor material (the passkey ceremony runs here). */
  readonly resolveFactor: (factor: UnlockFactor, transfer: ArrayBuffer[]) => Promise<Factor>;
  /** The create/import factor gate: required on an uninitialized vault, forbidden after. */
  readonly createFactorParam: (
    factor: InitialFactor | undefined,
    transfer: ArrayBuffer[],
  ) => Promise<Factor | undefined>;
  /** Adopts the session a create/import result opened onto the channel. */
  readonly sessionOf: (result: { readonly session: string }) => void;
};

const internals = new WeakMap<Wallet, WalletInternals>();

export function registerInternals(wallet: Wallet, value: WalletInternals): void {
  internals.set(wallet, value);
}

/**
 * The internals behind a Wallet from this package — or `invalid-input` for anything else. A foreign
 * object can imitate the Wallet shape but can never hold the channel: modules that look it up here
 * get a closed failure, not a crafted kernel.
 */
export function internalsOf(wallet: Wallet): WalletInternals {
  const found = internals.get(wallet);
  if (found === undefined) {
    throw new WalletError("invalid-input", "not a Wallet from @qntx/wallet");
  }
  return found;
}
