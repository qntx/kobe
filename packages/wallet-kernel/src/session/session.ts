import { bytesToHex } from "@noble/hashes/utils.js";

import type { LockReason } from "@qntx/wallet/types";

import { KernelError } from "../errors.ts";
import type { KernelPlatform } from "../platform.ts";
import type { Secret } from "../secret/secret.ts";
import { wipe } from "../secret/secret.ts";

/**
 * Factor material resolved while creating a wallet on an uninitialized vault. The KEK is expensive
 * (600k PBKDF2) or single-use (PRF), so it is derived once at `createMnemonic` and held in the
 * draft until `confirm`/`discard`/`lock`.
 */
export type PendingFactor =
  | { readonly kind: "password"; readonly kek: Secret; readonly salt: Uint8Array }
  | { readonly kind: "passkey"; readonly kek: Secret; readonly credentialId: Uint8Array };

/** An in-flight mnemonic ceremony: entropy plus the expected quiz answers. Lock discards all. */
export type MnemonicDraft = {
  readonly entropy: Secret;
  readonly words: 12 | 24;
  readonly quiz: readonly [number, number, number];
  readonly expected: ReadonlyArray<Uint8Array>;
  readonly pendingFactor: PendingFactor | undefined;
};

type State =
  | { readonly status: "uninitialized" }
  | { readonly status: "locked" }
  | {
      readonly status: "unlocked";
      readonly id: string;
      readonly dek: Secret;
      /** The vault keyId the DEK belongs to — a keyId change elsewhere invalidates the session. */
      readonly keyId: string;
      readonly unlockedAt: number; // elapsed clock
      lastActivityAt: number; // elapsed clock
    };

function wipePendingFactor(pending: PendingFactor): void {
  pending.kek.wipe();
  if (pending.kind === "password") {
    wipe(pending.salt);
  } else {
    wipe(pending.credentialId);
  }
}

export function wipeDraft(draft: MnemonicDraft): void {
  draft.entropy.wipe();
  for (const expected of draft.expected) {
    wipe(expected);
  }
  if (draft.pendingFactor !== undefined) {
    wipePendingFactor(draft.pendingFactor);
  }
}

/**
 * Session state machine: uninitialized | locked | unlocked. Timeout checks run at the start of
 * every request (the authoritative path); the injected `platform.setTimer` additionally locks
 * proactively so a quiet Worker still locks on time.
 */
export class Session {
  private state: State = { status: "uninitialized" };
  private readonly drafts = new Map<string, MnemonicDraft>();
  private cancelTimer: (() => void) | undefined;
  private readonly platform: KernelPlatform;
  private readonly onLock: (reason: LockReason) => void;

  constructor(platform: KernelPlatform, onLock: (reason: LockReason) => void) {
    this.platform = platform;
    this.onLock = onLock;
  }

  get status(): "uninitialized" | "locked" | "unlocked" {
    return this.state.status;
  }

  get unlocked(): boolean {
    return this.state.status === "unlocked";
  }

  /** Called once the initial store image is loaded and after every external change. */
  setInitialized(initialized: boolean): void {
    if (this.state.status === "uninitialized" && initialized) {
      this.state = { status: "locked" };
    } else if (!initialized && this.state.status !== "uninitialized") {
      // The vault was wiped externally (reset in another tab): the session is invalidated.
      this.lock("invalidated");
      this.state = { status: "uninitialized" };
    }
  }

  /** Opens a session, replacing any existing one. Returns the new session id. */
  open(dek: Secret, keyId: string): string {
    this.wipeUnlocked();
    const id = bytesToHex(this.platform.random(16));
    const at = this.platform.elapsed();
    this.state = { status: "unlocked", id, dek, keyId, unlockedAt: at, lastActivityAt: at };
    this.schedule();
    return id;
  }

  /** Swaps the live DEK after a rotation commit (old DEK wiped); throws `locked` when not unlocked. */
  rotate(dek: Secret, keyId: string): void {
    const { state } = this;
    if (state.status !== "unlocked") {
      throw new KernelError("locked", "session is not unlocked");
    }
    state.dek.wipe();
    this.state = { ...state, dek, keyId };
  }

  /**
   * Enforces idle and max-session deadlines on the monotonic elapsed clock. Returns the lock reason
   * when the session expired; the caller locks before handling the request. Pure check — activity
   * is stamped by `touch()` on a successful request, never here.
   */
  checkTimeouts(): LockReason | undefined {
    const { state } = this;
    if (state.status !== "unlocked") {
      return undefined;
    }
    const now = this.platform.elapsed();
    if (now - state.unlockedAt > this.platform.policy.maxSessionMs) {
      return "expired";
    }
    if (now - state.lastActivityAt > this.platform.policy.idleMs) {
      return "idle";
    }
    return undefined;
  }

  /**
   * Stamps user activity: the idle deadline moves forward and the timer re-arms. The max-session
   * deadline never moves — `schedule()` still clamps to it.
   */
  touch(): void {
    const { state } = this;
    if (state.status !== "unlocked") {
      return;
    }
    state.lastActivityAt = this.platform.elapsed();
    this.schedule();
  }

  /** The live session for a request that carries `session`; throws `locked` on any mismatch. */
  require(requestSession: string | undefined): { id: string; dek: Secret } {
    const { state } = this;
    if (state.status !== "unlocked" || requestSession !== state.id) {
      throw new KernelError("locked", "session is not unlocked");
    }
    return { id: state.id, dek: state.dek };
  }

  /** The live session without a request-id check (drafts prove same-process provenance). */
  current(): { id: string; dek: Secret; keyId: string } {
    const { state } = this;
    if (state.status !== "unlocked") {
      throw new KernelError("locked", "session is not unlocked");
    }
    return { id: state.id, dek: state.dek, keyId: state.keyId };
  }

  putDraft(id: string, draft: MnemonicDraft): void {
    const existing = this.drafts.get(id);
    if (existing !== undefined) {
      wipeDraft(existing);
    }
    this.drafts.set(id, draft);
  }

  takeDraft(id: string): MnemonicDraft {
    const draft = this.drafts.get(id);
    if (draft === undefined) {
      throw new KernelError("not-found", "unknown draft");
    }
    this.drafts.delete(id);
    return draft;
  }

  /** Peek without removing: a wrong quiz answer keeps the draft. */
  getDraft(id: string): MnemonicDraft {
    const draft = this.drafts.get(id);
    if (draft === undefined) {
      throw new KernelError("not-found", "unknown draft");
    }
    return draft;
  }

  dropDraft(id: string): void {
    const draft = this.drafts.get(id);
    if (draft !== undefined) {
      this.drafts.delete(id);
      wipeDraft(draft);
    }
  }

  lock(reason: LockReason): void {
    const wasUnlocked = this.state.status === "unlocked";
    this.wipeUnlocked();
    for (const draft of this.drafts.values()) {
      wipeDraft(draft);
    }
    this.drafts.clear();
    this.state = { status: this.state.status === "uninitialized" ? "uninitialized" : "locked" };
    if (wasUnlocked) {
      this.onLock(reason);
    }
  }

  private wipeUnlocked(): void {
    if (this.state.status === "unlocked") {
      this.state.dek.wipe();
    }
    if (this.cancelTimer !== undefined) {
      this.cancelTimer();
      this.cancelTimer = undefined;
    }
  }

  private schedule(): void {
    if (this.state.status !== "unlocked") {
      return;
    }
    const now = this.platform.elapsed();
    const deadline = Math.min(
      this.state.unlockedAt + this.platform.policy.maxSessionMs,
      this.state.lastActivityAt + this.platform.policy.idleMs,
    );
    const delay = Math.max(0, deadline - now);
    if (this.cancelTimer !== undefined) {
      this.cancelTimer();
    }
    this.cancelTimer = this.platform.setTimer(delay, () => {
      const reason = this.checkTimeouts();
      if (reason === undefined) {
        this.schedule();
      } else {
        this.lock(reason);
      }
    });
  }
}
