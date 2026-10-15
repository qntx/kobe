/**
 * The host side of the kernel channel (design/enclave.mdx "协议与传输"): port lifecycle, respawn,
 * request/response correlation and wire validation. Internal to the `./host` subpath — reserved for
 * host packages (wallet-worker, wallet-native); applications must not use it.
 */
import {
  isProtocolValue,
  kernelEvent,
  METHODS,
  PROTOCOL_VERSION,
  responseError,
  ValidationError,
} from "./protocol/index.ts";
import type { MethodName, ParamsOf, ProtocolValue, ResultOf } from "./protocol/index.ts";
import { WalletError } from "./types.ts";
import type { LockReason, StatusPayload } from "./types.ts";

/** The host packages' side of the kernel channel (worker, JSI runtime, in-process test port). */
export type MainPort = {
  readonly post: (message: ProtocolValue, transfer: ArrayBuffer[]) => void;
  readonly listen: (handler: (message: unknown) => void) => () => void;
  readonly onExit: (handler: () => void) => () => void;
  readonly terminate: () => void;
};

export function integrity(message: string): WalletError {
  return new WalletError("integrity", message);
}

/** Schedules `fn` after `delayMs` and returns a cancel function — injected by the host package. */
export type SetTimer = (delayMs: number, fn: () => void) => () => void;

/** A silent kernel is a wedged kernel: every call gets this long before the port is replaced. */
const CALL_TIMEOUT_MS = 60_000;

type Pending = {
  readonly method: MethodName;
  readonly resolve: (value: unknown) => void;
  readonly reject: (error: WalletError) => void;
  readonly cancelTimer: () => void;
};

/**
 * State callbacks: the channel owns the port lifecycle and message ordering; the wallet owns the
 * snapshot state these events describe. `onLocked`/`onCrashed` fire before the port is replaced so
 * the wallet can stamp the lock reason.
 */
export type ChannelHandlers = {
  readonly onStatus: (status: StatusPayload) => void;
  readonly onLocked: (reason: LockReason) => void;
  readonly onCrashed: () => void;
};

export class Channel {
  /** The live kernel session; attached to every request and cleared whenever it is gone. */
  session: string | undefined;

  private port: MainPort | undefined;
  private unlisten: (() => void) | undefined;
  private unlistenExit: (() => void) | undefined;
  private generation = 0;

  private readonly pending = new Map<number, Pending>();
  private nextId = 1;
  private destroyed = false;
  /** Terminal state: the kernel peer proved untrustworthy; every later call fails with it. */
  private broken: WalletError | undefined;
  /** Whether the current port has delivered its first valid status event. */
  private portReady = false;
  private readyPromise: Promise<void>;
  private resolveReady: (() => void) | undefined;
  private rejectReady: ((error: WalletError) => void) | undefined;

  private readonly spawn: () => MainPort;
  private readonly handlers: ChannelHandlers;
  private readonly setTimer: SetTimer;

  constructor(spawn: () => MainPort, handlers: ChannelHandlers, setTimer: SetTimer) {
    this.spawn = spawn;
    this.handlers = handlers;
    this.setTimer = setTimer;
    this.readyPromise = new Promise((resolve, reject) => {
      this.resolveReady = resolve;
      this.rejectReady = reject;
    });
  }

  /** Spawns the first kernel and resolves once its initial status event arrives. */
  async start(): Promise<void> {
    this.respawn();
    return this.readyPromise;
  }

  /** Resolves when the current port has delivered its first status event. */
  get ready(): Promise<void> {
    return this.readyPromise;
  }

  /**
   * Terminates the current port and spawns a fresh secret runtime, keeping the vault image (the
   * host-side store survives the worker). "Lock destroys the enclave."
   */
  respawn(): void {
    if (this.destroyed || this.broken !== undefined) {
      return;
    }
    this.unlisten?.();
    this.unlistenExit?.();
    this.port?.terminate();
    this.port = undefined;
    this.session = undefined;
    this.portReady = false;

    const generation = ++this.generation;
    // Settle the previous gate: a call still awaiting it must not hang — the kernel it was
    // waiting for is gone, so "locked" (session destroyed) applies.
    // oxlint-disable-next-line promise/prefer-await-to-then -- marks the stale gate as handled without swallowing it for awaiters
    void this.readyPromise.catch(() => undefined);
    this.rejectReady?.(new WalletError("locked", "the kernel restarted"));
    this.readyPromise = new Promise((resolve, reject) => {
      this.resolveReady = resolve;
      this.rejectReady = reject;
    });
    // A rejected gate with nobody awaiting it (e.g. destroy() mid-boot) must not surface as
    // an unhandled rejection; callers that do await still observe the rejection.
    // oxlint-disable-next-line promise/prefer-await-to-then -- marks the gate as handled without swallowing it for awaiters
    void this.readyPromise.catch(() => undefined);
    try {
      const port = this.spawn();
      this.unlisten = port.listen((message) => {
        this.onMessage(message, generation);
      });
      this.unlistenExit = port.onExit(() => {
        this.onExit(generation);
      });
      this.port = port;
    } catch {
      // A host that cannot spawn has no kernel to talk to — fail closed like a dead peer.
      this.breakChannel(integrity("could not spawn the kernel port"));
    }
  }

  private onExit(generation: number): void {
    if (generation !== this.generation || this.destroyed || this.broken !== undefined) {
      return;
    }
    this.session = undefined;
    if (!this.portReady) {
      // Death before the first valid status means the runtime never ran honestly (worker
      // blocked by CSP, a script that fails to load, protocol skew): no respawn — a fresh
      // spawn would face the same broken peer. Initial connect rejects with integrity;
      // a respawned port dying this way breaks the wallet.
      this.breakChannel(integrity("the kernel port died before its first status"));
      return;
    }
    // A proven port dying is a crash: fail everything in flight, mark it, respawn.
    this.failPending(new WalletError("crashed", "the kernel port exited"));
    this.handlers.onCrashed();
    this.respawn();
  }

  /**
   * Immediate host-side lock: no kernel round trip. Fails everything in flight with `locked`, drops
   * the session, reports the user lock, and replaces the port — the old worker can never answer
   * again. Safe mid-commit: IndexedDB transactions are atomic.
   */
  lockNow(): void {
    if (this.destroyed || this.broken !== undefined) {
      return;
    }
    this.session = undefined;
    this.failPending(new WalletError("locked", "the vault locked"));
    this.handlers.onLocked("user");
    this.respawn();
  }

  private onCallTimeout(): void {
    if (this.destroyed || this.broken !== undefined) {
      return;
    }
    this.failPending(new WalletError("crashed", "the kernel did not answer in time"));
    this.handlers.onCrashed();
    this.respawn();
  }

  private failPending(error: WalletError): void {
    for (const [, pending] of this.pending) {
      pending.cancelTimer();
      pending.reject(error);
    }
    this.pending.clear();
  }

  /** Removes the pending entry (cancelling its timeout) and runs `fn` on it. */
  private settle(id: number, fn: (pending: Pending) => void): void {
    const pending = this.pending.get(id);
    if (pending !== undefined) {
      pending.cancelTimer();
      this.pending.delete(id);
      fn(pending);
    }
  }

  /**
   * Terminal failure: terminate the port, fail everything in flight, and latch `broken` so every
   * later call rejects with the same error. The snapshot is left untouched.
   */
  private breakChannel(error: WalletError): void {
    this.broken = error;
    this.session = undefined;
    this.failPending(error);
    this.rejectReady?.(error);
    this.unlisten?.();
    this.unlistenExit?.();
    this.port?.terminate();
    this.port = undefined;
    this.generation++; // anything the dead port still emits is stale
  }

  /** A malformed protocol peer cannot be trusted — it fails closed, never respawns. */
  private poison(reason: string): void {
    this.breakChannel(integrity(reason));
  }

  private onMessage(raw: unknown, generation: number): void {
    if (generation !== this.generation) {
      return; // a dead port must not steer the wallet
    }
    if (
      !isProtocolValue(raw) ||
      typeof raw !== "object" ||
      raw === null ||
      raw instanceof Uint8Array ||
      Array.isArray(raw)
    ) {
      this.poison("malformed kernel message");
      return;
    }
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- narrowed to a plain record above
    const message = raw as Readonly<Record<string, ProtocolValue>>;
    if ("id" in message) {
      this.onResponse(message);
      return;
    }
    if ("event" in message) {
      let event;
      try {
        event = kernelEvent(message);
      } catch (error) {
        if (!(error instanceof ValidationError)) {
          throw error;
        }
        this.poison("malformed kernel event");
        return;
      }
      if (event.event === "status") {
        if (event.status.vault !== "unlocked") {
          this.session = undefined;
        }
        this.portReady = true;
        this.handlers.onStatus(event.status);
        this.resolveReady?.();
      } else {
        // A locked event destroys the enclave: drop the session, tear down the port, respawn.
        this.session = undefined;
        this.handlers.onLocked(event.reason);
        this.failPending(new WalletError("locked", "the vault locked"));
        this.respawn();
      }
      return;
    }
    this.poison("unrecognised kernel message");
  }

  private onResponse(message: Readonly<Record<string, ProtocolValue>>): void {
    const { id } = message;
    if (typeof id !== "number" || !Number.isSafeInteger(id) || message["v"] !== PROTOCOL_VERSION) {
      this.poison("malformed response envelope");
      return;
    }
    const pending = this.pending.get(id);
    if (pending === undefined) {
      // Includes UNATTRIBUTED_ID 0 — never a live request.
      this.poison("response for an unknown request");
      return;
    }
    const hasOk = "ok" in message;
    const hasErr = "err" in message;
    if (hasOk === hasErr) {
      // Keep the entry so poison's failPending rejects this caller too.
      this.poison("malformed response body");
      return;
    }
    if (hasErr) {
      try {
        const err = responseError(message["err"]);
        this.settle(id, (p) => {
          p.reject(
            new WalletError(
              err.code,
              `kernel returned ${err.code}`,
              typeof err.retryAt === "number" ? err.retryAt : undefined,
            ),
          );
        });
      } catch (error) {
        if (!(error instanceof ValidationError)) {
          throw error;
        }
        this.poison("malformed error payload");
      }
      return;
    }
    try {
      const result = METHODS[pending.method].result(message["ok"]);
      this.settle(id, (p) => {
        p.resolve(result);
      });
    } catch (error) {
      if (!(error instanceof ValidationError)) {
        throw error;
      }
      this.poison("invalid result from the kernel");
    }
  }

  /**
   * Sends one request and resolves with the validated result. The kernel answers with status →
   * response → locked, so the snapshot is already current when this promise settles.
   */
  async call<M extends MethodName>(
    method: M,
    params: ParamsOf<M>,
    transfer: ArrayBuffer[] = [],
  ): Promise<ResultOf<M>> {
    await this.readyPromise;
    if (this.broken !== undefined) {
      throw this.broken;
    }
    const { port } = this;
    if (this.destroyed || port === undefined) {
      throw new WalletError("locked", "wallet is destroyed");
    }
    const id = this.nextId++;
    const message: Record<string, ProtocolValue> = { v: PROTOCOL_VERSION, id, method, params };
    // Attach the session whenever we hold one: the create/import methods are session:false
    // in the table because the rule is dynamic (required exactly when the vault is initialized).
    if (this.session !== undefined) {
      message["session"] = this.session;
    }
    const result = await new Promise<unknown>((resolve, reject) => {
      const cancelTimer = this.setTimer(CALL_TIMEOUT_MS, () => {
        this.onCallTimeout();
      });
      this.pending.set(id, { method, resolve, reject, cancelTimer });
      try {
        port.post(message, transfer);
      } catch {
        cancelTimer();
        this.pending.delete(id);
        reject(integrity("the kernel port refused the message"));
      }
    });
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- validated by METHODS[method].result
    return result as ResultOf<M>;
  }

  /** Terminates the port without respawn; later calls fail "locked". */
  destroy(): void {
    if (this.destroyed) {
      return;
    }
    this.destroyed = true;
    this.unlisten?.();
    this.unlistenExit?.();
    this.port?.terminate();
    this.port = undefined;
    this.session = undefined;
    this.rejectReady?.(new WalletError("locked", "wallet is destroyed"));
    this.failPending(new WalletError("locked", "wallet is destroyed"));
  }
}
