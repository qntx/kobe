/**
 * The proxy NostrSigner: the ref resolves against the CURRENT snapshot at every call, so the same
 * signer object keeps working across lock/unlock and worker respawns. Returned events are checked
 * against the request — a compromised kernel cannot make a valid signature over different content
 * pass as the requested event.
 */
import { signedMatchesUnsigned, verifyEvent } from "@qntx/nostr";
import type { UnsignedEvent } from "@qntx/nostr";

import { integrity } from "../channel.ts";
import type { WalletInternals } from "../internal.ts";
import type { UnsignedEventInput } from "../protocol/index.ts";
import { WalletError } from "../types.ts";
import type { NostrKeyInfo, NostrKeyRef } from "../types.ts";
import type { NostrUnwrapResult, WalletSigner } from "./types.ts";

/** Resolves a public ref to its stored key record; missing refs are `not-found`. */
export function keyInfoOf(internals: WalletInternals, ref: NostrKeyRef): NostrKeyInfo {
  const info = internals.snapshot().nostr.keys.find((key) => {
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

export function proxySigner(ref: NostrKeyRef, internals: WalletInternals): WalletSigner {
  const resolvePublicKey = (): string => keyInfoOf(internals, ref).publicKey;
  return {
    getPublicKey: async () => {
      await internals.ready();
      return resolvePublicKey();
    },
    signEvent: async (unsigned) => {
      const publicKey = resolvePublicKey();
      // An absent pubkey must stay absent: `pubkey: undefined` is not a ProtocolValue and the
      // kernel would reject the params outright.
      const event: UnsignedEventInput =
        unsigned.pubkey === undefined
          ? {
              kind: unsigned.kind,
              created_at: unsigned.created_at,
              tags: unsigned.tags,
              content: unsigned.content,
            }
          : {
              kind: unsigned.kind,
              created_at: unsigned.created_at,
              tags: unsigned.tags,
              content: unsigned.content,
              pubkey: unsigned.pubkey,
            };
      const signed = await internals.call("nostr.signEvent", { publicKey, event });
      // The kernel output must be the requested event, signed by the expected key.
      const requested: UnsignedEvent = {
        kind: unsigned.kind,
        created_at: unsigned.created_at,
        tags: unsigned.tags,
        content: unsigned.content,
        pubkey: publicKey,
      };
      if (
        signed.pubkey !== publicKey ||
        !signedMatchesUnsigned(signed, requested) ||
        !verifyEvent(signed)
      ) {
        throw integrity("the kernel returned a forged event");
      }
      return signed;
    },
    nip04Encrypt: async (peer, plaintext) =>
      internals.call("nostr.nip04Encrypt", {
        publicKey: resolvePublicKey(),
        peer,
        text: plaintext,
      }),
    nip04Decrypt: async (peer, ciphertext) =>
      internals.call("nostr.nip04Decrypt", {
        publicKey: resolvePublicKey(),
        peer,
        text: ciphertext,
      }),
    nip44Encrypt: async (peer, plaintext) =>
      internals.call("nostr.nip44Encrypt", {
        publicKey: resolvePublicKey(),
        peer,
        text: plaintext,
      }),
    nip44Decrypt: async (peer, payload) =>
      internals.call("nostr.nip44Decrypt", {
        publicKey: resolvePublicKey(),
        peer,
        text: payload,
      }),
    unwrapGiftWraps: async (events): Promise<ReadonlyArray<NostrUnwrapResult>> => {
      const result = await internals.call("nostr.unwrapGiftWraps", {
        publicKey: resolvePublicKey(),
        events: [...events],
      });
      return result.results;
    },
  };
}
