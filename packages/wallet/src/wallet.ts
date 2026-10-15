/**
 * The host-facing `Wallet` (design/entry.mdx "API"): snapshot state, the core API groups, and the
 * glue between the kernel `Channel` and factor resolution. `connectKernel` is exported under the
 * `./host` subpath — reserved for host packages; applications must not use it. Protocol modules
 * (@qntx/wallet/nostr and future siblings) reach this wallet's channel through the registered
 * internals in internal.ts — never through the public type.
 */
import { Channel } from "./channel.ts";
import type { MainPort, SetTimer } from "./channel.ts";
import {
  PASSKEY_PURPOSE_WALLET,
  passkeyName,
  requireCeremony,
  resolveFactor,
  resolveInitialFactor,
  vaultSaltBytes,
  walletSaltBytes,
  wireBytes,
  wireSecretText,
} from "./factors.ts";
import type { FactorSource, PasskeyCeremony } from "./factors.ts";
import { registerInternals } from "./internal.ts";
import type { Factor } from "./protocol/index.ts";
import { SingleUseSecret } from "./secret.ts";
import { WalletError } from "./types.ts";
import type {
  DataKeyApi,
  ExportedSecret,
  FactorInfo,
  InitialFactor,
  LockReason,
  MnemonicDraft,
  PasskeyConfig,
  StatusPayload,
  UnlockFactor,
  VaultApi,
  Wallet,
  WalletInfo,
  WalletSnapshot,
  WalletsApi,
} from "./types.ts";

export type ConnectOptions = {
  readonly spawn: () => MainPort;
  readonly passkey: PasskeyConfig;
  readonly ceremony: PasskeyCeremony | undefined;
  /** Timer source injected by the host package (globalThis timers on web/node). */
  readonly setTimer: SetTimer;
  /** Runs once inside `destroy()` — host-side cleanup (page listeners, timers). */
  readonly onDestroy?: () => void;
};

/** Structural equality over plain snapshot data (validated protocol payloads only). */
function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) {
    return true;
  }
  if (typeof a !== "object" || a === null || typeof b !== "object" || b === null) {
    return false;
  }
  if (Array.isArray(a) || Array.isArray(b)) {
    return (
      Array.isArray(a) &&
      Array.isArray(b) &&
      a.length === b.length &&
      a.every((item, index) => deepEqual(item, b[index]))
    );
  }
  const aKeys = Object.keys(a);
  const bKeys = Object.keys(b);
  return (
    aKeys.length === bKeys.length &&
    aKeys.every(
      (key) =>
        key in b &&
        deepEqual(
          (a as Record<string, unknown>)[key], // oxlint-disable-line typescript/no-unsafe-type-assertion -- plain-object records
          (b as Record<string, unknown>)[key], // oxlint-disable-line typescript/no-unsafe-type-assertion -- plain-object records
        ),
    )
  );
}

export class KernelWallet implements Wallet {
  private readonly channel: Channel;
  private readonly passkeyCfg: PasskeyConfig;
  private readonly ceremony: PasskeyCeremony | undefined;
  private readonly onDestroy: (() => void) | undefined;
  private destroyed = false;

  private status: StatusPayload | undefined;
  private lockReason: LockReason | undefined;
  private verifying = 0;
  private snapshotValue: WalletSnapshot;
  private readonly listeners = new Set<() => void>();

  private constructor(options: ConnectOptions) {
    this.passkeyCfg = options.passkey;
    this.ceremony = options.ceremony;
    this.onDestroy = options.onDestroy;
    this.snapshotValue = {
      vault: "uninitialized",
      lockReason: undefined,
      verifying: false,
      factors: [],
      wallets: [],
      nostr: { keys: [] },
    };
    this.channel = new Channel(
      options.spawn,
      {
        onStatus: (status) => {
          this.onStatus(status);
        },
        onLocked: (reason) => {
          this.lockReason = reason;
          this.emit();
        },
        onCrashed: () => {
          this.lockReason = "crashed";
          this.markLocked();
        },
      },
      options.setTimer,
    );
    registerInternals(this, {
      call: async (method, params, transfer) => this.channel.call(method, params, transfer),
      ready: async () => this.channel.ready,
      snapshot: () => this.snapshotValue,
      withVerifying: async (fn) => this.withVerifying(fn),
      resolveFactor: async (factor, transfer) => resolveFactor(this.factorSource, factor, transfer),
      createFactorParam: async (factor, transfer) => this.createFactorParam(factor, transfer),
      sessionOf: (result) => {
        this.sessionOf(result);
      },
    });
  }

  static async connect(options: ConnectOptions): Promise<KernelWallet> {
    const wallet = new KernelWallet(options);
    await wallet.channel.start();
    return wallet;
  }

  /**
   * The worker is dead or replaced — no status will arrive from it, yet an unlocked vault is locked
   * now. Reflect that in the snapshot without waiting for the respawned kernel; other states
   * (uninitialized, corrupted, …) are the kernel's truth and stay untouched.
   */
  private markLocked(): void {
    if (this.status !== undefined && this.status.vault === "unlocked") {
      this.status = { ...this.status, vault: "locked" };
    }
    this.emit();
  }

  private onStatus(status: StatusPayload): void {
    if (this.lockReason === undefined && status.vault === "locked") {
      this.lockReason = "cold-start"; // locked at first sight, not by an action of ours
    }
    this.status = status;
    this.emit();
  }

  /**
   * Rebuilds the immutable snapshot and notifies subscribers — only when the content actually
   * changed (identical status events produce no new reference and no notification).
   */
  private emit(): void {
    const { status } = this;
    const next: WalletSnapshot = {
      vault: status === undefined ? "uninitialized" : status.vault,
      lockReason: this.lockReason,
      verifying: this.verifying > 0,
      factors: status === undefined ? [] : status.factors,
      wallets: status === undefined ? [] : status.wallets,
      nostr: { keys: status === undefined ? [] : status.nostr.keys },
    };
    const current = this.snapshotValue;
    if (
      current.vault === next.vault &&
      current.lockReason === next.lockReason &&
      current.verifying === next.verifying &&
      deepEqual(current.factors, next.factors) &&
      deepEqual(current.wallets, next.wallets) &&
      deepEqual(current.nostr, next.nostr)
    ) {
      return;
    }
    this.snapshotValue = next;
    for (const listener of this.listeners) {
      listener();
    }
  }

  // Arrow properties: safe unbound, e.g. useSyncExternalStore(wallet.subscribe, wallet.getSnapshot).
  readonly getSnapshot = (): WalletSnapshot => this.snapshotValue;

  readonly subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  private get factorSource(): FactorSource {
    return {
      passkey: this.passkeyCfg,
      ceremony: this.ceremony,
      factors: () => this.snapshotValue.factors,
    };
  }

  /** True while a ceremony or a factor-bearing request is in flight; drives `verifying`. */
  private async withVerifying<T>(fn: () => Promise<T>): Promise<T> {
    this.verifying++;
    this.emit();
    try {
      return await fn();
    } finally {
      this.verifying--;
      this.emit();
    }
  }

  private initialized(): boolean {
    return this.snapshotValue.vault !== "uninitialized";
  }

  /** The factor gate on create/import commands; keeps useless ceremonies from firing. */
  private async createFactorParam(
    factor: InitialFactor | undefined,
    transfer: ArrayBuffer[],
  ): Promise<Factor | undefined> {
    if (this.initialized()) {
      if (factor !== undefined) {
        throw new WalletError("invalid-input", "the vault is already initialized");
      }
      return undefined;
    }
    if (factor === undefined) {
      throw new WalletError("invalid-input", "an initial factor is required");
    }
    return resolveInitialFactor(this.factorSource, factor, transfer);
  }

  private sessionOf(result: { readonly session: string }): void {
    this.channel.session = result.session;
  }

  readonly vault: VaultApi = {
    unlock: async (factor?: UnlockFactor): Promise<void> =>
      this.withVerifying(async () => {
        const transfer: ArrayBuffer[] = [];
        const wire = await resolveFactor(
          this.factorSource,
          factor ?? { kind: "passkey" },
          transfer,
        );
        const result = await this.channel.call("vault.unlock", { factor: wire }, transfer);
        this.sessionOf(result);
      }),
    // Host-side lock: immediate, no kernel round trip — fails pending calls, clears the session
    // and respawns the port. Idempotent: re-locking is a no-op.
    // oxlint-disable-next-line typescript/require-await -- the interface's Promise is resolved synchronously
    lock: async (): Promise<void> => {
      this.channel.lockNow();
      this.markLocked();
    },
    addFactor: async (factor: InitialFactor, verify: UnlockFactor): Promise<FactorInfo> =>
      this.withVerifying(async () => {
        const transfer: ArrayBuffer[] = [];
        const wireVerify = await resolveFactor(this.factorSource, verify, transfer);
        const wireFactor = await resolveInitialFactor(this.factorSource, factor, transfer);
        return this.channel.call(
          "vault.addFactor",
          { verify: wireVerify, factor: wireFactor },
          transfer,
        );
      }),
    removeFactor: async (id: string, verify: UnlockFactor): Promise<void> =>
      this.withVerifying(async () => {
        const transfer: ArrayBuffer[] = [];
        const wireVerify = await resolveFactor(this.factorSource, verify, transfer);
        await this.channel.call("vault.removeFactor", { verify: wireVerify, id }, transfer);
      }),
    reset: async (): Promise<void> => {
      await this.channel.call("vault.reset", null);
    },
  };

  readonly wallets: WalletsApi = {
    createWithPasskey: async (options: {
      readonly name: string;
      readonly factor?: InitialFactor;
    }): Promise<WalletInfo> =>
      this.withVerifying(async () => {
        const ceremony = requireCeremony(this.factorSource);
        const name = passkeyName(options.name);
        const transfer: ArrayBuffer[] = [];
        const result = await ceremony.create({
          purpose: "wallet",
          name,
          salts: {
            first: walletSaltBytes(this.factorSource),
            second: vaultSaltBytes(this.factorSource),
          },
        });
        let factor: Factor | undefined;
        if (this.initialized()) {
          if (options.factor !== undefined) {
            throw new WalletError("invalid-input", "the vault is already initialized");
          }
          result.second?.fill(0); // the vault factor slot is not needed
        } else {
          factor = await resolveInitialFactor(this.factorSource, options.factor, transfer, result);
        }
        const created = await this.channel.call(
          "wallet.createWithPasskey",
          {
            credentialId: wireBytes(result.credentialId, transfer),
            prfWallet: wireBytes(result.first, transfer, true),
            ...(factor === undefined ? {} : { factor }),
          },
          transfer,
        );
        this.sessionOf(created);
        return created.wallet;
      }),
    restoreWithPasskey: async (options?: {
      readonly factor?: InitialFactor;
    }): Promise<WalletInfo> =>
      this.withVerifying(async () => {
        const ceremony = requireCeremony(this.factorSource);
        const transfer: ArrayBuffer[] = [];
        const result = await ceremony.assert({
          salts: {
            first: walletSaltBytes(this.factorSource),
            second: vaultSaltBytes(this.factorSource),
          },
        });
        // The asserted credential must be a wallet-purpose passkey: a vault-purpose credential
        // would silently derive a different wallet. Rejected assertions never reach the kernel.
        if (result.userHandle?.[0] !== PASSKEY_PURPOSE_WALLET) {
          result.first.fill(0);
          result.second?.fill(0);
          throw new WalletError("wrong-passkey", "the passkey is not a wallet credential");
        }
        let factor: Factor | undefined;
        if (this.initialized()) {
          if (options?.factor !== undefined) {
            throw new WalletError("invalid-input", "the vault is already initialized");
          }
          result.second?.fill(0);
        } else {
          factor = await resolveInitialFactor(this.factorSource, options?.factor, transfer, result);
        }
        const created = await this.channel.call(
          "wallet.restoreWithPasskey",
          {
            credentialId: wireBytes(result.credentialId, transfer),
            prfWallet: wireBytes(result.first, transfer, true),
            ...(factor === undefined ? {} : { factor }),
          },
          transfer,
        );
        this.sessionOf(created);
        return created.wallet;
      }),
    createMnemonic: async (options: {
      readonly words: 12 | 24;
      readonly factor?: InitialFactor;
    }): Promise<MnemonicDraft> => {
      const transfer: ArrayBuffer[] = [];
      const factor = await this.createFactorParam(options.factor, transfer);
      const created = await this.channel.call(
        "wallet.createMnemonic",
        { words: options.words, ...(factor === undefined ? {} : { factor }) },
        transfer,
      );
      const draftId = created.draft;
      return {
        words: new SingleUseSecret(created.words),
        quiz: created.quiz,
        confirm: async (answers: ReadonlyArray<string>): Promise<WalletInfo> => {
          const answerTransfer: ArrayBuffer[] = [];
          const encoded = answers.map((word) => wireSecretText(word, answerTransfer));
          const confirmed = await this.channel.call(
            "wallet.confirmMnemonic",
            { draft: draftId, answers: encoded },
            answerTransfer,
          );
          this.sessionOf(confirmed);
          return confirmed.wallet;
        },
        discard: async (): Promise<void> => {
          await this.channel.call("wallet.discardMnemonic", { draft: draftId });
        },
      };
    },
    importMnemonic: async (options: {
      readonly mnemonic: string;
      readonly factor?: InitialFactor;
    }): Promise<WalletInfo> => {
      const transfer: ArrayBuffer[] = [];
      const factor = await this.createFactorParam(options.factor, transfer);
      const mnemonic = wireSecretText(options.mnemonic, transfer);
      const created = await this.channel.call(
        "wallet.importMnemonic",
        { mnemonic, ...(factor === undefined ? {} : { factor }) },
        transfer,
      );
      this.sessionOf(created);
      return created.wallet;
    },
    exportMnemonic: async (walletId: string, verify: UnlockFactor): Promise<ExportedSecret> =>
      this.withVerifying(async () => {
        const transfer: ArrayBuffer[] = [];
        const wireVerify = await resolveFactor(this.factorSource, verify, transfer);
        const bytes = await this.channel.call(
          "wallet.exportMnemonic",
          { verify: wireVerify, walletId },
          transfer,
        );
        return new SingleUseSecret(bytes);
      }),
    delete: async (walletId: string, verify: UnlockFactor): Promise<void> =>
      this.withVerifying(async () => {
        const transfer: ArrayBuffer[] = [];
        const wireVerify = await resolveFactor(this.factorSource, verify, transfer);
        await this.channel.call("wallet.delete", { verify: wireVerify, walletId }, transfer);
      }),
  };

  readonly dataKeys: DataKeyApi = {
    get: async (purpose: string): Promise<Uint8Array> =>
      this.channel.call("dataKeys.get", { purpose }),
  };

  // oxlint-disable-next-line typescript/require-await -- the interface's Promise is resolved synchronously
  async destroy(): Promise<void> {
    if (this.destroyed) {
      return;
    }
    this.destroyed = true;
    this.onDestroy?.();
    this.channel.destroy();
  }
}

/**
 * Validates the passkey configuration: the RP identity and both PRF salts are permanent
 * identifiers, so an empty or colliding value is rejected here rather than producing unrecoverable
 * credentials later.
 */
function checkPasskeyConfig(passkey: PasskeyConfig): void {
  const { rpId, rpName, walletSalt, vaultSalt } = passkey;
  if (
    rpId.length === 0 ||
    rpName.length === 0 ||
    walletSalt.length === 0 ||
    vaultSalt.length === 0 ||
    walletSalt === vaultSalt
  ) {
    throw new WalletError(
      "invalid-input",
      "passkey config requires a non-empty rpId, rpName and two different salts",
    );
  }
}

/**
 * Connects a kernel spawned by the host package and returns the host-facing `Wallet`. The first
 * spawn must deliver a status event before this resolves.
 */
export async function connectKernel(options: ConnectOptions): Promise<Wallet> {
  checkPasskeyConfig(options.passkey);
  return KernelWallet.connect(options);
}
