import type { MethodName, ParamsOf, ResultOf } from "@qntx/wallet/protocol";

import type { KernelPlatform } from "../platform.ts";
import type { Session } from "../session/session.ts";
import type { StoreOp, VaultImage } from "../vault/store.ts";
import type { OpenedRecord } from "../vault/vault.ts";

/**
 * The vault-facing hooks a protocol module implements, wired once in kernel.ts — an explicit
 * composition point, not a registry. The core iterates `KernelContext.modules` without knowing what
 * any module's records mean; status sections are composed separately in status.ts.
 */
export type VaultHooks = {
  /** Whether the module owns stored record `kind` — an unclaimed stored kind corrupts the vault. */
  readonly ownsRecord: (kind: string) => boolean;
  /**
   * Claims the module's plaintexts out of an unlock pass. Claimed plaintexts are consumed (the
   * module wipes them into its own state); the records it returns unclaimed are passed to the next
   * module and finally wiped by the caller.
   */
  readonly claimUnlocked: (records: ReadonlyArray<OpenedRecord>) => ReadonlyArray<OpenedRecord>;
  /** Lock bookkeeping: dispose every secret the module holds. */
  readonly lock: () => void;
  /**
   * The extra ops committed atomically when a wallet is deleted — the module's records derived from
   * that walletId. `after` runs once the commit lands (evicting the keys from live state).
   */
  readonly walletDeleteOps: (
    image: VaultImage,
    walletId: string,
  ) => { readonly ops: ReadonlyArray<StoreOp>; readonly after: () => void };
};

/**
 * Services and state a command handler needs. `image` is replaced after every commit or external
 * change; `commit` writes, reloads `image`, and marks the status event dirty.
 */
export type KernelContext = {
  readonly platform: KernelPlatform;
  readonly session: Session;
  readonly modules: ReadonlyArray<VaultHooks>;
  image: VaultImage;
  /**
   * The vault image cannot be trusted: set on a failed store load, a public header that fails to
   * parse, a stored kind no module owns, or a record that fails authentication after the DEK
   * opened. While true only `status` and `vault.reset` are served; a successful commit recomputes
   * and can clear it.
   */
  corrupted: boolean;
  readonly commit: (ops: ReadonlyArray<StoreOp>) => Promise<void>;
};

/**
 * One typed handler per protocol method; `ParamsOf`/`ResultOf` come from the METHODS validators, so
 * a handler whose shape drifts from the table fails to typecheck. Params are validated once in
 * `dispatch`, generically, before the handler runs.
 */
export type Handler<M extends MethodName> = (
  ctx: KernelContext,
  params: ParamsOf<M>,
  session: string | undefined,
) => Promise<ResultOf<M>> | ResultOf<M>;
