import type { SignerPool } from "../nostr/pool.ts";
import type { KernelPlatform } from "../platform.ts";
import type { Session } from "../session/session.ts";
import type { StoreOp, VaultImage } from "../vault/store.ts";

/**
 * Services and state a command handler needs. `image` is replaced after every commit or external
 * change; `commit` writes, reloads `image`, and marks the status event dirty.
 */
export type KernelContext = {
  readonly platform: KernelPlatform;
  readonly session: Session;
  readonly pool: SignerPool;
  image: VaultImage;
  /**
   * The vault image cannot be trusted: set on a failed store load, a public header that fails to
   * parse, or a record that fails authentication after the DEK opened. While true only `status` and
   * `vault.reset` are served; a successful commit recomputes and can clear it.
   */
  corrupted: boolean;
  readonly commit: (ops: ReadonlyArray<StoreOp>) => Promise<void>;
};
