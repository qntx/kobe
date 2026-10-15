/**
 * The nostr module of @qntx/wallet: `nostr(wallet)` returns the wallet's Nostr API — signer
 * proxies, key discovery/derivation/import/generation, guarded export and removal. The API is
 * memoized per wallet so repeated calls return the same object (stable React identity); a foreign
 * object is rejected because only a Wallet from this package holds a registered channel.
 */
import { wireSecretText } from "../factors.ts";
import { internalsOf } from "../internal.ts";
import type { WalletInternals } from "../internal.ts";
import { SingleUseSecret } from "../secret.ts";
import { WalletError } from "../types.ts";
import type {
  DerivedNostrKey,
  ExportedSecret,
  InitialFactor,
  NostrKeyInfo,
  NostrKeyRef,
  UnlockFactor,
  Wallet,
} from "../types.ts";
import { keyInfoOf, proxySigner } from "./signer.ts";
import type { NostrApi, NostrExportKeyFormat, NostrImportKeyInput, WalletSigner } from "./types.ts";

export type {
  DerivedNostrKey,
  NostrApi,
  NostrExportKeyFormat,
  NostrImportKeyInput,
  NostrKeyInfo,
  NostrKeyRef,
  NostrUnwrapResult,
  WalletSigner,
} from "./types.ts";

function createNostrApi(internals: WalletInternals): NostrApi {
  return {
    signer: (ref: NostrKeyRef): WalletSigner => proxySigner(ref, internals),

    discover: async (
      walletId: string,
      from: number,
      count: number,
    ): Promise<ReadonlyArray<DerivedNostrKey>> => {
      const result = await internals.call("nostr.discover", { walletId, from, count });
      return result.keys;
    },

    deriveKey: async (walletId: string, groupIndex: number): Promise<NostrKeyInfo> =>
      internals.call("nostr.deriveKey", { walletId, groupIndex }),

    importKey: async (
      input: NostrImportKeyInput,
      options?: { readonly factor?: InitialFactor },
    ): Promise<NostrKeyInfo> => {
      const transfer: ArrayBuffer[] = [];
      const factor = await internals.createFactorParam(options?.factor, transfer);
      const wireInput =
        "nsec" in input
          ? { kind: "nsec" as const, nsec: wireSecretText(input.nsec, transfer) }
          : {
              kind: "ncryptsec" as const,
              ncryptsec: input.ncryptsec,
              password: wireSecretText(input.password, transfer),
            };
      const result = await internals.call(
        "nostr.importKey",
        { input: wireInput, ...(factor === undefined ? {} : { factor }) },
        transfer,
      );
      internals.sessionOf(result);
      return result.key;
    },

    generateKey: async (options?: { readonly factor?: InitialFactor }): Promise<NostrKeyInfo> => {
      const transfer: ArrayBuffer[] = [];
      const factor = await internals.createFactorParam(options?.factor, transfer);
      const result = await internals.call(
        "nostr.generateKey",
        factor === undefined ? {} : { factor },
        transfer,
      );
      internals.sessionOf(result);
      return result.key;
    },

    createNip46ClientKey: async (): Promise<NostrKeyInfo> =>
      internals.call("nostr.createNip46ClientKey", null),

    removeKey: async (ref: NostrKeyRef, verify?: UnlockFactor): Promise<void> =>
      internals.withVerifying(async () => {
        const info = keyInfoOf(internals, ref); // resolves ref → publicKey + origin
        const transfer: ArrayBuffer[] = [];
        let wireVerify;
        if (info.origin !== "nip46-client") {
          if (verify === undefined) {
            throw new WalletError("invalid-input", "factor verification is required");
          }
          wireVerify = await internals.resolveFactor(verify, transfer);
        }
        await internals.call(
          "nostr.removeKey",
          {
            publicKey: info.publicKey,
            ...(wireVerify === undefined ? {} : { verify: wireVerify }),
          },
          transfer,
        );
      }),

    exportKey: async (
      ref: NostrKeyRef,
      format: NostrExportKeyFormat,
      verify: UnlockFactor,
    ): Promise<ExportedSecret> =>
      internals.withVerifying(async () => {
        const { publicKey } = keyInfoOf(internals, ref);
        const transfer: ArrayBuffer[] = [];
        const wireVerify = await internals.resolveFactor(verify, transfer);
        const wireFormat =
          format.kind === "nsec"
            ? { kind: "nsec" as const }
            : {
                kind: "ncryptsec" as const,
                password: wireSecretText(format.password, transfer),
              };
        const bytes = await internals.call(
          "nostr.exportKey",
          { verify: wireVerify, publicKey, format: wireFormat },
          transfer,
        );
        return new SingleUseSecret(bytes);
      }),
  };
}

const apis = new WeakMap<Wallet, NostrApi>();

export function nostr(wallet: Wallet): NostrApi {
  const internals = internalsOf(wallet);
  let api = apis.get(wallet);
  if (api === undefined) {
    api = createNostrApi(internals);
    apis.set(wallet, api);
  }
  return api;
}
