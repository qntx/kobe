/**
 * The host-facing `Wallet` (design/entry.mdx "API"): snapshot state, the API groups, and the glue
 * between the kernel `Channel`, factor resolution and proxy signers. `connectKernel` is exported
 * under the `./host` subpath — reserved for host packages; applications must not use it.
 */
import { Channel } from "./channel.ts";
import type { MainPort } from "./channel.ts";
import {
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
import type { Factor } from "./protocol/index.ts";
import { SingleUseSecret } from "./secret.ts";
import { proxySigner } from "./signer.ts";
import { WalletError } from "./types.ts";
import type {
  DataKeyApi,
  DerivedNostrKey,
  ExportApi,
  ExportedSecret,
  FactorInfo,
  InitialFactor,
  LockReason,
  MnemonicDraft,
  NostrApi,
  NostrKeyInfo,
  NostrKeyRef,
  PasskeyConfig,
  StatusPayload,
  UnlockFactor,
  VaultApi,
  Wallet,
  WalletCreated,
  WalletSigner,
  WalletSnapshot,
  WalletsApi,
} from "./types.ts";

export type ConnectOptions = {
  readonly spawn: () => MainPort;
  readonly passkey: PasskeyConfig;
  readonly ceremony: PasskeyCeremony | undefined;
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

  private status: StatusPayload | undefined;
  private lockReason: LockReason | undefined;
  private verifying = 0;
  private snapshotValue: WalletSnapshot;
  private readonly listeners = new Set<() => void>();

  private constructor(options: ConnectOptions) {
    this.passkeyCfg = options.passkey;
    this.ceremony = options.ceremony;
    this.snapshotValue = {
      vault: "uninitialized",
      lockReason: undefined,
      verifying: false,
      factors: [],
      wallets: [],
      nostrKeys: [],
    };
    this.channel = new Channel(options.spawn, {
      onStatus: (status) => {
        this.onStatus(status);
      },
      onLocked: (reason) => {
        this.lockReason = reason;
        this.emit();
      },
      onCrashed: () => {
        this.lockReason = "crashed";
        this.emit();
      },
    });
  }

  static async connect(options: ConnectOptions): Promise<KernelWallet> {
    const wallet = new KernelWallet(options);
    await wallet.channel.start();
    return wallet;
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
      nostrKeys: status === undefined ? [] : status.nostrKeys,
    };
    const current = this.snapshotValue;
    if (
      current.vault === next.vault &&
      current.lockReason === next.lockReason &&
      current.verifying === next.verifying &&
      deepEqual(current.factors, next.factors) &&
      deepEqual(current.wallets, next.wallets) &&
      deepEqual(current.nostrKeys, next.nostrKeys)
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

  private sessionOf(result: { session: string }): string {
    this.channel.session = result.session;
    return result.session;
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
    lock: async (): Promise<void> => {
      try {
        await this.channel.call("vault.lock", null);
      } catch (error) {
        // Locking an already-locked (or just-locked) vault is the postcondition anyway.
        if (!(error instanceof WalletError) || error.code !== "locked") {
          throw error;
        }
      }
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
    }): Promise<WalletCreated> =>
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
        return { wallet: created.wallet, nostr: created.nostr };
      }),
    restoreWithPasskey: async (options?: {
      readonly factor?: InitialFactor;
    }): Promise<WalletCreated> =>
      this.withVerifying(async () => {
        const ceremony = requireCeremony(this.factorSource);
        const transfer: ArrayBuffer[] = [];
        const result = await ceremony.assert({
          salts: {
            first: walletSaltBytes(this.factorSource),
            second: vaultSaltBytes(this.factorSource),
          },
        });
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
        return { wallet: created.wallet, nostr: created.nostr };
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
        confirm: async (answers: ReadonlyArray<string>): Promise<WalletCreated> => {
          const answerTransfer: ArrayBuffer[] = [];
          const encoded = answers.map((word) => wireSecretText(word, answerTransfer));
          const confirmed = await this.channel.call(
            "wallet.confirmMnemonic",
            { draft: draftId, answers: encoded },
            answerTransfer,
          );
          this.sessionOf(confirmed);
          return { wallet: confirmed.wallet, nostr: confirmed.nostr };
        },
        discard: async (): Promise<void> => {
          await this.channel.call("wallet.discardMnemonic", { draft: draftId });
        },
      };
    },
    importMnemonic: async (options: {
      readonly mnemonic: string;
      readonly factor?: InitialFactor;
    }): Promise<WalletCreated> => {
      const transfer: ArrayBuffer[] = [];
      const factor = await this.createFactorParam(options.factor, transfer);
      const mnemonic = wireSecretText(options.mnemonic, transfer);
      const created = await this.channel.call(
        "wallet.importMnemonic",
        { mnemonic, ...(factor === undefined ? {} : { factor }) },
        transfer,
      );
      this.sessionOf(created);
      return { wallet: created.wallet, nostr: created.nostr };
    },
    discoverNostr: async (
      walletId: string,
      from: number,
      count: number,
    ): Promise<ReadonlyArray<DerivedNostrKey>> => {
      const result = await this.channel.call("wallet.discoverNostr", { walletId, from, count });
      return result.keys;
    },
    delete: async (walletId: string, verify: UnlockFactor): Promise<void> =>
      this.withVerifying(async () => {
        const transfer: ArrayBuffer[] = [];
        const wireVerify = await resolveFactor(this.factorSource, verify, transfer);
        await this.channel.call("wallet.delete", { verify: wireVerify, walletId }, transfer);
      }),
  };

  readonly nostr: NostrApi = {
    signer: (ref: NostrKeyRef): WalletSigner =>
      proxySigner(ref, this.channel, (key) => this.resolveRef(key)),
    deriveKey: async (walletId: string, groupIndex: number): Promise<NostrKeyInfo> =>
      this.channel.call("nostr.deriveKey", { walletId, groupIndex }),
    importKey: async (
      input: { readonly nsec: string } | { readonly ncryptsec: string; readonly password: string },
      options?: { readonly factor?: InitialFactor },
    ): Promise<NostrKeyInfo> => {
      const transfer: ArrayBuffer[] = [];
      const factor = await this.createFactorParam(options?.factor, transfer);
      const wireInput =
        "nsec" in input
          ? { kind: "nsec" as const, nsec: wireSecretText(input.nsec, transfer) }
          : {
              kind: "ncryptsec" as const,
              ncryptsec: input.ncryptsec,
              password: wireSecretText(input.password, transfer),
            };
      const result = await this.channel.call(
        "nostr.importKey",
        { input: wireInput, ...(factor === undefined ? {} : { factor }) },
        transfer,
      );
      this.sessionOf(result);
      return result.key;
    },
    generateKey: async (options?: { readonly factor?: InitialFactor }): Promise<NostrKeyInfo> => {
      const transfer: ArrayBuffer[] = [];
      const factor = await this.createFactorParam(options?.factor, transfer);
      const result = await this.channel.call(
        "nostr.generateKey",
        factor === undefined ? {} : { factor },
        transfer,
      );
      this.sessionOf(result);
      return result.key;
    },
    createNip46ClientKey: async (): Promise<NostrKeyInfo> =>
      this.channel.call("nostr.createNip46ClientKey", null),
    removeKey: async (ref: NostrKeyRef, verify?: UnlockFactor): Promise<void> =>
      this.withVerifying(async () => {
        const info = this.keyInfo(ref); // resolves ref → publicKey + origin from the snapshot
        const transfer: ArrayBuffer[] = [];
        let wireVerify: Factor | undefined;
        if (info.origin !== "nip46-client") {
          if (verify === undefined) {
            throw new WalletError("invalid-input", "factor verification is required");
          }
          wireVerify = await resolveFactor(this.factorSource, verify, transfer);
        }
        await this.channel.call(
          "nostr.removeKey",
          {
            publicKey: info.publicKey,
            ...(wireVerify === undefined ? {} : { verify: wireVerify }),
          },
          transfer,
        );
      }),
  };

  readonly exports: ExportApi = {
    mnemonic: async (walletId: string, verify: UnlockFactor): Promise<ExportedSecret> =>
      this.withVerifying(async () => {
        const transfer: ArrayBuffer[] = [];
        const wireVerify = await resolveFactor(this.factorSource, verify, transfer);
        const bytes = await this.channel.call(
          "export.mnemonic",
          { verify: wireVerify, walletId },
          transfer,
        );
        return new SingleUseSecret(bytes);
      }),
    nostrKey: async (
      ref: NostrKeyRef,
      format: { readonly kind: "nsec" } | { readonly kind: "ncryptsec"; readonly password: string },
      verify: UnlockFactor,
    ): Promise<ExportedSecret> =>
      this.withVerifying(async () => {
        const publicKey = this.resolveRef(ref);
        const transfer: ArrayBuffer[] = [];
        const wireVerify = await resolveFactor(this.factorSource, verify, transfer);
        const wireFormat =
          format.kind === "nsec"
            ? { kind: "nsec" as const }
            : {
                kind: "ncryptsec" as const,
                password: wireSecretText(format.password, transfer),
              };
        const bytes = await this.channel.call(
          "export.nostrKey",
          { verify: wireVerify, publicKey, format: wireFormat },
          transfer,
        );
        return new SingleUseSecret(bytes);
      }),
  };

  readonly dataKeys: DataKeyApi = {
    get: async (purpose: string): Promise<Uint8Array> =>
      this.channel.call("dataKeys.get", { purpose }),
  };

  // oxlint-disable-next-line typescript/require-await -- the interface's Promise is resolved synchronously
  async destroy(): Promise<void> {
    this.channel.destroy();
  }

  /** Resolves a public ref to its stored key record; missing refs are `not-found`. */
  private keyInfo(ref: NostrKeyRef): NostrKeyInfo {
    const info = this.snapshotValue.nostrKeys.find((key) => {
      const k = key.ref;
      return (
        (ref.kind === "derived" &&
          k.kind === "derived" &&
          k.walletId === ref.walletId &&
          k.groupIndex === ref.groupIndex) ||
        (ref.kind === "nip46-client" && k.kind === "nip46-client" && k.id === ref.id) ||
        (ref.kind === "standalone" && k.kind === "standalone" && k.id === ref.id)
      );
    });
    if (info === undefined) {
      throw new WalletError("not-found", "no such nostr key");
    }
    return info;
  }

  private resolveRef(ref: NostrKeyRef): string {
    return this.keyInfo(ref).publicKey;
  }
}

/**
 * Connects a kernel spawned by the host package and returns the host-facing `Wallet`. The first
 * spawn must deliver a status event before this resolves.
 */
export async function connectKernel(options: ConnectOptions): Promise<Wallet> {
  return KernelWallet.connect(options);
}
