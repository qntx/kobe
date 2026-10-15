/**
 * RecordStore over a MessagePort RPC: the vault image (ciphertext + public headers) lives in the
 * main thread so a lock can destroy the whole worker without losing the vault. The main side pushes
 * a "changed" notice when some other writer committed; `watch` relays it to the kernel. A failed
 * request comes back as `{ t: "failed", code }` and rejects — never left hanging.
 */
import { KernelError } from "@qntx/wallet-kernel";
import type { KernelErrorCode, RecordStore, StoreOp, VaultImage } from "@qntx/wallet-kernel";
import { walletErrorCode } from "@qntx/wallet/protocol";

import type { StorePort, StoreReply, StoreRequest } from "../shared.ts";
import { assertVaultImage } from "../shared.ts";

type Pending = {
  readonly resolve: (reply: StoreReply) => void;
  readonly reject: (error: Error) => void;
};

/** The code on a `failed` reply is only trusted if it is a real WalletErrorCode. */
function replyCode(code: unknown): KernelErrorCode {
  try {
    return walletErrorCode(code);
  } catch {
    return "unavailable";
  }
}

export function createStoreClient(port: StorePort): RecordStore {
  let nextId = 1;
  const pending = new Map<number, Pending>();
  const watchers = new Set<() => void>();

  port.listen((raw) => {
    // Internal channel between this package's two halves — a malformed message means the host
    // wiring is broken; dropping it is safer than guessing.
    if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
      return;
    }
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- internal wire shape; malformed payloads are dropped by the t-checks
    const reply = raw as StoreReply;
    if (reply.t === "changed") {
      for (const watcher of watchers) {
        watcher();
      }
      return;
    }
    if (reply.t === "loaded" || reply.t === "committed" || reply.t === "failed") {
      const entry = pending.get(reply.id);
      if (entry !== undefined) {
        pending.delete(reply.id);
        if (reply.t === "failed") {
          entry.reject(new KernelError(replyCode(reply.code), "vault store: request failed"));
        } else {
          entry.resolve(reply);
        }
      }
    }
  });

  async function request(
    build: (id: number) => StoreRequest,
    pick: (reply: StoreReply) => VaultImage | undefined,
  ): Promise<VaultImage | undefined> {
    const id = nextId++;
    return new Promise((resolve, reject) => {
      pending.set(id, {
        resolve: (reply) => {
          resolve(pick(reply));
        },
        reject,
      });
      try {
        port.post(build(id));
      } catch (error) {
        pending.delete(id);
        reject(error instanceof Error ? error : new Error(String(error)));
      }
    });
  }

  return {
    async load(): Promise<VaultImage> {
      const reply = await request(
        (id) => ({ t: "load", id }),
        (r) => (r.t === "loaded" ? assertVaultImage(r.image) : undefined),
      );
      if (reply === undefined) {
        throw new Error("store: malformed load reply");
      }
      return reply;
    },
    async commit(ops: ReadonlyArray<StoreOp>): Promise<void> {
      await request(
        (id) => ({ t: "commit", id, ops }),
        () => undefined,
      );
    },
    watch(listener) {
      watchers.add(listener);
      return () => {
        watchers.delete(listener);
      };
    },
  };
}
