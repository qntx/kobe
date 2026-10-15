import { equalBytes } from "@noble/ciphers/utils.js";

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
import type { LockReason } from "@qntx/wallet/types";

import type { CommitOptions, Handler, KernelContext } from "./commands/context.ts";
import { CORE_HANDLERS } from "./commands/index.ts";
import { KernelError } from "./errors.ts";
import { createNostrModule } from "./modules/nostr/index.ts";
import type { KernelPlatform, Port } from "./platform.ts";
import { wipe } from "./secret/secret.ts";
import { Session } from "./session/session.ts";
import { statusContents, statusPayload } from "./status.ts";
import { factorBindingOk } from "./vault/factors.ts";
import type { StoredRecord, StoreOp, VaultImage } from "./vault/store.ts";
import { openRecord } from "./vault/vault.ts";
import type { OpenedRecord } from "./vault/vault.ts";

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

/** Counter ops never fence: they fold into the store atomically against whatever is there. */
function isCounterOp(op: StoreOp): boolean {
  return op.op === "record-failure" || op.op === "reset-failures";
}

/** Whether the commit needs the `expect-revision` guard prepended (see KernelContext.commit). */
function needsGuard(ops: ReadonlyArray<StoreOp>): boolean {
  return (
    ops[0]?.op !== "init" &&
    !ops.some((op) => op.op === "clear") &&
    !ops.every(isCounterOp) &&
    !ops.some((op) => op.op === "expect-revision")
  );
}

function classifyLoadFailure(error: unknown): "corrupted" | "unsupported" | "unavailable" {
  if (error instanceof KernelError) {
    if (error.code === "unsupported") {
      return "unsupported";
    }
    if (error.code === "integrity") {
      return "corrupted";
    }
  }
  return "unavailable";
}

export function startKernel(platform: KernelPlatform, port: Port): void {
  // The module composition is explicit and static: the nostr module owns its handler table, its
  // VaultHooks entry in ctx.modules and its status section; there is no registry — future modules
  // add a line here and a section in status.ts's composition.
  const nostr = createNostrModule();
  const HANDLERS = {
    status: (ctx: KernelContext) => statusPayload(ctx, nostr),
    ...CORE_HANDLERS,
    ...nostr.handlers,
  } satisfies { [M in MethodName]: Handler<M> };

  let dirty = false; // a commit happened since the last status event
  let inRequest = false; // a request is being dispatched — locks defer their event
  let pendingLock: LockReason | undefined;
  // An authenticated-open failure (a sealed record the DEK could not open) proves the vault is
  // corrupt beyond what public headers show: latched until the vault becomes uninitialized.
  let integrityFailure = false;

  /** Health transitions while unlocked invalidate the session immediately — except unavailable. */
  const setHealth = (next: KernelContext["health"]): void => {
    ctx.health = next;
    if (next === "corrupted" || next === "unsupported") {
      ctx.session.lock("invalidated"); // no-op unless unlocked
    }
  };

  /**
   * Reconciles live module state from `prev` to `ctx.image` under the unlocked session (S6):
   * records are diffed by (kind, id) — removals go to the owning module's `forget`, additions and
   * changes are opened with the session DEK and claimed (unclaimed plaintexts are wiped); changed
   * factor rows are verified against the session DEK's binding tag. A keyId mismatch or any
   * authentication failure latches `corrupted` and invalidates the session. No-op while locked.
   */
  const reconcile = (prev: VaultImage): void => {
    if (!ctx.session.unlocked) {
      return;
    }
    const { dek, keyId } = ctx.session.current();
    const next = ctx.image;
    if (next.meta === undefined || next.meta.keyId !== keyId) {
      // The vault rotated elsewhere: this session's DEK is stale — lock it.
      ctx.session.lock("invalidated");
      return;
    }
    const opened: OpenedRecord[] = [];
    let handedOff = false;
    try {
      const before = new Map<string, StoredRecord>();
      for (const record of prev.records) {
        before.set(`${record.kind}/${record.id}`, record);
      }
      for (const record of next.records) {
        const prior = before.get(`${record.kind}/${record.id}`);
        if (prior === undefined) {
          opened.push({ kind: record.kind, id: record.id, plaintext: openRecord(dek, record) });
        } else {
          before.delete(`${record.kind}/${record.id}`);
          if (prior.header !== record.header || !equalBytes(prior.sealed, record.sealed)) {
            opened.push({ kind: record.kind, id: record.id, plaintext: openRecord(dek, record) });
          }
        }
      }
      for (const removed of before.values()) {
        for (const module of ctx.modules) {
          if (module.ownsRecord(removed.kind)) {
            module.forget(removed.kind, removed.id);
          }
        }
      }
      let unclaimed: ReadonlyArray<OpenedRecord> = opened;
      for (const module of ctx.modules) {
        unclaimed = module.claimUnlocked(unclaimed);
      }
      handedOff = true;
      for (const record of unclaimed) {
        wipe(record.plaintext);
      }
      const priorFactors = new Map(prev.factors.map((factor) => [factor.id, factor]));
      for (const factor of next.factors) {
        const prior = priorFactors.get(factor.id);
        const changed =
          prior === undefined ||
          prior.header !== factor.header ||
          !equalBytes(prior.sealed, factor.sealed);
        if (changed && !factorBindingOk(dek, factor)) {
          throw new KernelError(
            "integrity",
            "factor binding does not match the vault",
            undefined,
            true,
          );
        }
      }
    } catch {
      if (!handedOff) {
        for (const record of opened) {
          wipe(record.plaintext);
        }
      }
      integrityFailure = true;
      setHealth("corrupted");
    }
  };

  /**
   * Installs a freshly loaded image and recomputes health from it. The integrity latch wins over a
   * clean structural read until the vault is gone; `unsupported` wins over everything. While the
   * session is unlocked the live module state reconciles against the new image — a corrupted or
   * rotated vault locks it.
   */
  const applyImage = (image: VaultImage): void => {
    const prev = ctx.image;
    ctx.image = image;
    ctx.session.setInitialized(image.meta !== undefined);
    if (image.meta === undefined) {
      integrityFailure = false;
    }
    const assessed = statusContents(image, ctx.modules, nostr).health;
    setHealth(assessed === "ok" && integrityFailure ? "corrupted" : assessed);
    reconcile(prev);
  };

  const post = (message: ProtocolValue): void => {
    port.post(message, collectTransferables(message, []));
  };

  const postStatus = (): void => {
    const event: KernelEvent = {
      v: PROTOCOL_VERSION,
      event: "status",
      status: statusPayload(ctx, nostr),
    };
    post(event);
  };

  const onLock = (reason: LockReason): void => {
    for (const module of ctx.modules) {
      module.lock();
    }
    if (inRequest) {
      // Message ordering is status → response → locked: the request that caused the lock
      // (vault.reset, a timeout or invalidation at the top of the request) must still resolve.
      pendingLock = reason;
      return;
    }
    post({ v: PROTOCOL_VERSION, event: "locked", reason });
    postStatus();
  };

  const reload = async (): Promise<void> => {
    let image: VaultImage;
    try {
      image = await platform.store.load();
    } catch (error) {
      setHealth(classifyLoadFailure(error));
      throw error instanceof KernelError
        ? error
        : new KernelError("unavailable", "vault store: load failed");
    }
    applyImage(image);
  };

  const ctx: KernelContext = {
    platform,
    session: new Session(platform, onLock),
    modules: [nostr.vault],
    image: EMPTY_IMAGE,
    health: "ok",
    commit: async (ops: ReadonlyArray<StoreOp>, options?: CommitOptions) => {
      const guarded: StoreOp[] = needsGuard(ops)
        ? [{ op: "expect-revision", revision: ctx.image.meta?.revision ?? 0 }, ...ops]
        : [...ops];
      try {
        await platform.store.commit(guarded);
      } catch (error) {
        options?.rotate?.dek.wipe();
        if (error instanceof KernelError) {
          // The vault moved underneath us: pick up the winning image, then report the conflict.
          if (error.code === "conflict") {
            await reload().catch(() => undefined);
          }
          throw error;
        }
        setHealth("unavailable");
        throw new KernelError("unavailable", "vault store: commit failed");
      }
      if (options?.rotate !== undefined) {
        if (ctx.session.unlocked) {
          ctx.session.rotate(options.rotate.dek, options.rotate.keyId);
        } else {
          options.rotate.dek.wipe();
        }
      }
      // A reset lands as an uninitialized image here; the session follows without waiting
      // for the store watch (which may legitimately skip a host's own commits).
      dirty = true;
      await reload();
    },
    reload,
    reconcile,
  };

  const dispatch = async <M extends MethodName>(
    method: M,
    params: ProtocolValue,
    requestSession: string | undefined,
  ): Promise<ResultOf<M>> => {
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- METHODS[method].params output is ParamsOf<M>
    const parsed = METHODS[method].params(params) as ParamsOf<M>;
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- HANDLERS covers every MethodName; indexing with the generic M re-widens to the union
    const handler = HANDLERS[method] as Handler<M>;
    return handler(ctx, parsed, requestSession);
  };

  const handle = async (raw: unknown): Promise<void> => {
    // Timeouts are enforced before anything else, on every request.
    const vaultBefore = ctx.session.status;
    const healthBefore = ctx.health;
    let response: Response | undefined;
    inRequest = true;
    try {
      const expired = ctx.session.checkTimeouts();
      if (expired !== undefined) {
        ctx.session.lock(expired);
      }
      response = await respond(raw);
    } finally {
      inRequest = false;
    }
    if (dirty || ctx.session.status !== vaultBefore || ctx.health !== healthBefore) {
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
      // A vault that is not healthy cannot serve requests honestly: only status (answers from
      // the image in memory) and vault.reset (the recovery path) get through. A transient
      // failure retries one load before answering — a successful reload clears it.
      if (ctx.health !== "ok" && method !== "status" && method !== "vault.reset") {
        if (ctx.health === "unavailable") {
          await reload(); // throws the classified error, or restores health
        }
        if (ctx.health === "corrupted") {
          throw new KernelError("integrity", "the vault is corrupted");
        }
        if (ctx.health === "unsupported") {
          throw new KernelError("unsupported", "the vault needs a newer build");
        }
        if (ctx.health === "unavailable") {
          throw new KernelError("unavailable", "the vault store is unavailable");
        }
      }
      const result = await dispatch(
        method,
        params,
        typeof sessionField === "string" ? sessionField : undefined,
      );
      return { v: PROTOCOL_VERSION, id, ok: result };
    } catch (error) {
      // A corruption-marked error (a sealed record that failed authentication after the DEK
      // opened) latches the corrupted state until the vault is wiped or reset.
      if (error instanceof KernelError && error.corrupted) {
        integrityFailure = true;
        setHealth("corrupted");
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
  // A failed reload must not kill the enclave: reload classifies the failure into health and the
  // snapshot still goes out — from the image already in memory, or empty on startup.
  const reloadAndPost = async (): Promise<void> => {
    try {
      await reload();
    } catch {
      // Classified by reload; swallow so the queue tail never rejects.
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
