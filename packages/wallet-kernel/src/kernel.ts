import { isProtocolValue, METHODS, PROTOCOL_VERSION, UNATTRIBUTED_ID } from "@qntx/wallet/protocol";
import type {
  ErrorPayload,
  KernelEvent,
  MethodName,
  ParamsOf,
  ProtocolValue,
  Response,
  ResultOf,
} from "@qntx/wallet/protocol";
import type { LockReason, StatusPayload } from "@qntx/wallet/types";

import type { KernelContext } from "./commands/context.ts";
import * as nostrCommands from "./commands/nostr.ts";
import * as secretsCommands from "./commands/secrets.ts";
import * as vaultCommands from "./commands/vault.ts";
import * as walletCommands from "./commands/wallets.ts";
import { KernelError } from "./errors.ts";
import { SignerPool } from "./nostr/pool.ts";
import type { KernelPlatform, Port } from "./platform.ts";
import { Session } from "./session/session.ts";
import type { StoreOp, VaultImage } from "./vault/store.ts";
import { snapshotContents } from "./vault/vault.ts";

const EMPTY_IMAGE: VaultImage = { meta: undefined, records: [], factors: [] };

/** Buffers that may move to the host (exact-view Uint8Arrays only, depth-bounded). */
function collectTransferables(value: unknown, out: ArrayBuffer[], depth = 0): ArrayBuffer[] {
  if (depth > 8 || value === null || typeof value !== "object") {
    return out;
  }
  if (value instanceof Uint8Array) {
    if (
      value.buffer instanceof ArrayBuffer &&
      value.byteOffset === 0 &&
      value.byteLength === value.buffer.byteLength
    ) {
      out.push(value.buffer);
    }
    return out;
  }
  const items: ReadonlyArray<unknown> = Array.isArray(value) ? value : Object.values(value);
  for (const item of items) {
    collectTransferables(item, out, depth + 1);
  }
  return out;
}

function isMethodName(method: string): method is MethodName {
  return method in METHODS;
}

/** The `status` payload for the current session + image; shared by `status` and `postStatus`. */
function statusPayload(ctx: KernelContext): StatusPayload {
  const { factors, wallets, nostrKeys } = snapshotContents(ctx.image);
  return {
    protocol: PROTOCOL_VERSION,
    vault: ctx.corrupted ? "corrupted" : ctx.session.status,
    factors,
    wallets,
    nostrKeys,
  };
}

type Handler<M extends MethodName> = (
  ctx: KernelContext,
  params: ParamsOf<M>,
  session: string | undefined,
) => Promise<ResultOf<M>> | ResultOf<M>;

/**
 * One typed entry per protocol method; `ParamsOf`/`ResultOf` come from the METHODS validators, so a
 * handler whose shape drifts from the table fails to typecheck. Params are validated once in
 * `dispatch`, generically, before the handler runs.
 */
const HANDLERS: { [M in MethodName]: Handler<M> } = {
  status: (ctx) => statusPayload(ctx),
  "vault.unlock": async (ctx, params) => vaultCommands.unlockVault(ctx, params),
  "vault.lock": (ctx) => vaultCommands.lockVault(ctx),
  "vault.reset": async (ctx) => vaultCommands.resetVault(ctx),
  "vault.addFactor": async (ctx, params, session) => vaultCommands.addFactor(ctx, params, session),
  "vault.removeFactor": async (ctx, params, session) =>
    vaultCommands.removeFactor(ctx, params, session),
  "wallet.createWithPasskey": async (ctx, params, session) =>
    walletCommands.createWithPasskey(ctx, params, session),
  "wallet.restoreWithPasskey": async (ctx, params, session) =>
    walletCommands.createWithPasskey(ctx, params, session),
  "wallet.createMnemonic": async (ctx, params, session) =>
    walletCommands.createMnemonic(ctx, params, session),
  "wallet.confirmMnemonic": async (ctx, params) => walletCommands.confirmMnemonic(ctx, params),
  "wallet.discardMnemonic": (ctx, params) => walletCommands.discardMnemonic(ctx, params),
  "wallet.importMnemonic": async (ctx, params, session) =>
    walletCommands.importMnemonic(ctx, params, session),
  "wallet.discoverNostr": async (ctx, params, session) =>
    walletCommands.discoverNostr(ctx, params, session),
  "wallet.delete": async (ctx, params, session) =>
    walletCommands.deleteWallet(ctx, params, session),
  "nostr.deriveKey": async (ctx, params, session) => nostrCommands.deriveKey(ctx, params, session),
  "nostr.importKey": async (ctx, params, session) => nostrCommands.importKey(ctx, params, session),
  "nostr.generateKey": async (ctx, params, session) =>
    nostrCommands.generateKey(ctx, params, session),
  "nostr.createNip46ClientKey": async (ctx, _params, session) =>
    nostrCommands.createNip46ClientKey(ctx, session),
  "nostr.removeKey": async (ctx, params, session) => nostrCommands.removeKey(ctx, params, session),
  "nostr.signEvent": async (ctx, params, session) =>
    nostrCommands.signEventCommand(ctx, params, session),
  "nostr.nip04Encrypt": async (ctx, params, session) =>
    nostrCommands.nip04Encrypt(ctx, params, session),
  "nostr.nip04Decrypt": async (ctx, params, session) =>
    nostrCommands.nip04Decrypt(ctx, params, session),
  "nostr.nip44Encrypt": async (ctx, params, session) =>
    nostrCommands.nip44Encrypt(ctx, params, session),
  "nostr.nip44Decrypt": async (ctx, params, session) =>
    nostrCommands.nip44Decrypt(ctx, params, session),
  "nostr.unwrapGiftWraps": async (ctx, params, session) =>
    nostrCommands.unwrapGiftWraps(ctx, params, session),
  "export.mnemonic": async (ctx, params, session) =>
    secretsCommands.exportMnemonic(ctx, params, session),
  "export.nostrKey": async (ctx, params, session) =>
    secretsCommands.exportNostrKey(ctx, params, session),
  "dataKeys.get": async (ctx, params, session) => secretsCommands.getDataKey(ctx, params, session),
};

export function startKernel(platform: KernelPlatform, port: Port): void {
  const pool = new SignerPool();
  let dirty = false; // a commit happened since the last status event
  let inRequest = false; // a request is being dispatched — locks defer their event
  let pendingLock: LockReason | undefined;
  // Set when a store read throws: the rows cannot be trusted, so the vault latches
  // "corrupted" and requests answer "integrity" instead of running against an empty image —
  // and the enclave keeps serving errors rather than crashing (a crash would respawn into
  // the same broken store forever). A successful commit clears the flag, which keeps
  // vault.reset usable as the recovery path.
  let storeFailure: Error | undefined;

  const loadImage = async (): Promise<VaultImage> => {
    if (storeFailure !== undefined) {
      throw storeFailure;
    }
    try {
      return await platform.store.load();
    } catch (error) {
      storeFailure = error instanceof Error ? error : new Error(String(error));
      ctx.corrupted = true;
      throw storeFailure;
    }
  };

  /**
   * Installs a freshly loaded image and recomputes corruption from it — a public header that fails
   * to parse marks the vault corrupted, a clean load clears an earlier flag (vault.reset is the
   * recovery path; a sealed-record failure re-detects on the next unlock).
   */
  const applyImage = (image: VaultImage): void => {
    ctx.image = image;
    ctx.session.setInitialized(image.meta !== undefined);
    ctx.corrupted = snapshotContents(image).corrupted;
  };

  const post = (message: ProtocolValue): void => {
    port.post(message, collectTransferables(message, []));
  };

  const postStatus = (): void => {
    const event: KernelEvent = { v: PROTOCOL_VERSION, event: "status", status: statusPayload(ctx) };
    post(event);
  };

  const onLock = (reason: LockReason): void => {
    pool.dispose();
    if (inRequest) {
      // Message ordering is status → response → locked: the request that caused the lock
      // (vault.lock, vault.reset, a timeout at the top of the request) must still resolve.
      pendingLock = reason;
      return;
    }
    post({ v: PROTOCOL_VERSION, event: "locked", reason });
    postStatus();
  };

  const ctx: KernelContext = {
    platform,
    pool,
    session: new Session(platform, onLock),
    image: EMPTY_IMAGE,
    corrupted: false,
    commit: async (ops: ReadonlyArray<StoreOp>) => {
      await platform.store.commit(ops);
      // A commit re-establishes the store: clear any recorded failure so the
      // post-commit read actually runs (vault.reset is the corrupted-store recovery).
      storeFailure = undefined;
      // A reset lands as an uninitialized image here; the session follows without waiting
      // for the store watch (which may legitimately skip a host's own commits).
      applyImage(await loadImage());
      dirty = true;
    },
  };

  const reload = async (): Promise<void> => {
    applyImage(await loadImage());
  };

  const dispatch = async <M extends MethodName>(
    method: M,
    params: ProtocolValue,
    requestSession: string | undefined,
  ): Promise<ResultOf<M>> => {
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- METHODS[method].params output is ParamsOf<M>
    const parsed = METHODS[method].params(params) as ParamsOf<M>;
    const handler: Handler<M> = HANDLERS[method];
    return handler(ctx, parsed, requestSession);
  };

  const handle = async (raw: unknown): Promise<void> => {
    // Timeouts are enforced before anything else, on every request.
    const vaultBefore = ctx.session.status;
    const corruptedBefore = ctx.corrupted;
    let response: Response | undefined;
    inRequest = true;
    try {
      const expired = ctx.session.checkTimeouts(platform.now());
      if (expired !== undefined) {
        ctx.session.lock(expired);
      }
      response = await respond(raw);
    } finally {
      inRequest = false;
    }
    if (dirty || ctx.session.status !== vaultBefore || ctx.corrupted !== corruptedBefore) {
      dirty = false;
      postStatus();
    }
    if (response !== undefined) {
      post(response);
    }
    const lockedReason = pendingLock;
    pendingLock = undefined;
    if (lockedReason !== undefined) {
      post({ v: PROTOCOL_VERSION, event: "locked", reason: lockedReason });
    }
  };

  const respond = async (raw: unknown): Promise<Response> => {
    let id = UNATTRIBUTED_ID;
    try {
      if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
        throw new KernelError("integrity", "malformed request");
      }
      if (Object.getPrototypeOf(raw) !== Object.prototype) {
        throw new KernelError("integrity", "malformed request");
      }
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- narrowed to a plain object above
      const request = raw as Record<string, unknown>;
      const { v, id: requestId, method, session: sessionField } = request;
      if (v !== PROTOCOL_VERSION) {
        throw new KernelError("integrity", "protocol version mismatch");
      }
      if (typeof requestId !== "number" || !Number.isSafeInteger(requestId) || requestId < 0) {
        throw new KernelError("integrity", "malformed request id");
      }
      // The error is reported under the request id whenever it parses, so keep the
      // remaining envelope checks after this point.
      id = requestId;
      for (const key of Object.keys(request)) {
        if (
          key !== "v" &&
          key !== "id" &&
          key !== "method" &&
          key !== "session" &&
          key !== "params"
        ) {
          throw new KernelError("integrity", "unexpected request field");
        }
      }
      if (
        sessionField !== undefined &&
        (typeof sessionField !== "string" || sessionField.length > 64)
      ) {
        throw new KernelError("integrity", "malformed session field");
      }
      if (typeof method !== "string" || !isMethodName(method)) {
        throw new KernelError("integrity", "unknown method");
      }
      if (!("params" in request)) {
        throw new KernelError("integrity", "missing params");
      }
      const candidate = request["params"];
      if (!isProtocolValue(candidate)) {
        throw new KernelError("integrity", "malformed params");
      }
      const params: ProtocolValue = candidate;
      // A corrupted vault cannot serve requests honestly: report integrity for everything
      // except status (still answers from the image in memory) and vault.reset (the recovery
      // path — its commit clears the flag). No session is opened while corrupted.
      if (ctx.corrupted && method !== "status" && method !== "vault.reset") {
        throw new KernelError("integrity", "the vault is corrupted");
      }
      const result = await dispatch(
        method,
        params,
        typeof sessionField === "string" ? sessionField : undefined,
      );
      return { v: PROTOCOL_VERSION, id, ok: result };
    } catch (error) {
      // A corruption-marked error (a sealed record that failed authentication after the DEK
      // opened) latches the corrupted state for this kernel instance; it re-detects
      // deterministically after a respawn.
      if (error instanceof KernelError && error.corrupted) {
        ctx.corrupted = true;
      }
      const err: ErrorPayload =
        error instanceof KernelError
          ? error.retryAt === undefined
            ? { code: error.code }
            : { code: error.code, retryAt: error.retryAt }
          : { code: "integrity" };
      return { v: PROTOCOL_VERSION, id, err };
    }
  };

  // Requests are handled sequentially: only one factor-bearing operation runs at a time and
  // every handler sees a consistent image. The store watch joins the same queue so a reload can
  // never mutate ctx.image concurrently with a handler.
  let queue: Promise<void> = Promise.resolve();
  const enqueue = (task: () => Promise<void>): void => {
    // oxlint-disable-next-line promise/prefer-await-to-then -- the chain itself is the queue
    queue = queue.then(task, task);
  };

  // Other tabs/hosts commit through the same store; reload and rebroadcast the snapshot.
  // A failed reload must not kill the enclave: loadImage records the failure (requests now
  // answer "integrity") and the snapshot still goes out — from the image already in memory,
  // or empty on startup.
  const reloadAndPost = async (): Promise<void> => {
    try {
      await reload();
    } catch {
      // Recorded by loadImage; swallow so the queue tail never rejects.
    }
    postStatus();
  };

  platform.store.watch(() => {
    enqueue(reloadAndPost);
  });

  port.listen((message) => {
    enqueue(async () => handle(message));
  });

  enqueue(reloadAndPost);
}
