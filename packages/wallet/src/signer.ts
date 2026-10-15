/**
 * The proxy NostrSigner: the ref resolves against the CURRENT snapshot at every call, so the same
 * signer object keeps working across lock/unlock and worker respawns. Returned events are checked
 * against the request — a compromised kernel cannot make a valid signature over different content
 * pass as the requested event.
 */
import { signedMatchesUnsigned, verifyEvent } from "@qntx/nostr";
import type { UnsignedEvent } from "@qntx/nostr";

import { integrity } from "./channel.ts";
import type { Channel } from "./channel.ts";
import type { UnsignedEventInput } from "./protocol/index.ts";
import type { NostrKeyRef, NostrUnwrapResult, WalletSigner } from "./types.ts";

export function proxySigner(
  ref: NostrKeyRef,
  channel: Channel,
  resolvePublicKey: (ref: NostrKeyRef) => string,
): WalletSigner {
  return {
    getPublicKey: async () => {
      await channel.ready;
      return resolvePublicKey(ref);
    },
    signEvent: async (unsigned) => {
      const publicKey = resolvePublicKey(ref);
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
      const signed = await channel.call("nostr.signEvent", { publicKey, event });
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
      channel.call("nostr.nip04Encrypt", {
        publicKey: resolvePublicKey(ref),
        peer,
        text: plaintext,
      }),
    nip04Decrypt: async (peer, ciphertext) =>
      channel.call("nostr.nip04Decrypt", {
        publicKey: resolvePublicKey(ref),
        peer,
        text: ciphertext,
      }),
    nip44Encrypt: async (peer, plaintext) =>
      channel.call("nostr.nip44Encrypt", {
        publicKey: resolvePublicKey(ref),
        peer,
        text: plaintext,
      }),
    nip44Decrypt: async (peer, payload) =>
      channel.call("nostr.nip44Decrypt", {
        publicKey: resolvePublicKey(ref),
        peer,
        text: payload,
      }),
    unwrapGiftWraps: async (events): Promise<ReadonlyArray<NostrUnwrapResult>> => {
      const result = await channel.call("nostr.unwrapGiftWraps", {
        publicKey: resolvePublicKey(ref),
        events: [...events],
      });
      return result.results;
    },
  };
}
