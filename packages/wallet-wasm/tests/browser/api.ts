/**
 * The typed surface of `globalThis.qntx`, installed by the test page (page/main.ts). Specs call it
 * through `page.evaluate`; declaring it globally keeps the Node-side typecheck honest.
 */
import type { Event, UnsignedEvent } from "@qntx/nostr";
import type { NostrKeyRef, WalletCreated, WalletSnapshot } from "@qntx/wallet";

export type EvalResult<T = unknown> =
  | { readonly ok: true; readonly value: T }
  | {
      readonly ok: false;
      readonly code: string;
    };

export type QntxApi = {
  readonly stats: { spawned: number; terminated: number };
  readonly create: () => Promise<EvalResult<WalletSnapshot>>;
  readonly snapshot: () => WalletSnapshot;
  readonly createPasskey: () => Promise<EvalResult<WalletCreated>>;
  readonly createMnemonic: (
    password: string,
  ) => Promise<
    EvalResult<{ readonly words: ReadonlyArray<string>; readonly quiz: ReadonlyArray<number> }>
  >;
  readonly confirm: (answers: ReadonlyArray<string>) => Promise<EvalResult<WalletCreated>>;
  readonly lock: () => Promise<EvalResult>;
  readonly reset: () => Promise<EvalResult>;
  readonly unlockPassword: (password: string) => Promise<EvalResult>;
  readonly unlockPasskey: () => Promise<EvalResult>;
  readonly sign: (ref: NostrKeyRef, event: UnsignedEvent) => Promise<EvalResult<Event>>;
  readonly tamperBackedUp: () => Promise<{ readonly flipped: boolean }>;
  readonly tamperSealed: () => Promise<{ readonly written: boolean }>;
};

declare global {
  var qntx: QntxApi;
}
