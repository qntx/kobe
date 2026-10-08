/**
 * NIP-06 Nostr key derivation (`@qntx/kobe/nostr`).
 *
 * Derives Nostr keys from a core [`Wallet`] at `m/44'/1237'/<account>'/0/0` and formats them as
 * NIP-19 bech32 entities (`nsec`, `npub`). Signing and event handling belong to `@qntx/nostr`, not
 * here.
 */
export type { NostrAccount } from "./account.ts";
export { NostrDeriver } from "./deriver.ts";
