/**
 * Type-level contract: the wire event shapes declared in src/protocol/nostr.ts must stay
 * structurally compatible with @qntx/nostr's Event/UnsignedEvent/Rumor — the proxy signer feeds
 * kernel results straight into verifyEvent and Nip46Signer without conversion.
 */
import { describe, expect, it } from "vite-plus/test";

import type { Event, UnsignedEvent } from "@qntx/nostr";
import type { Rumor as Nip59Rumor } from "@qntx/nostr/nips/nip59";

import type { Rumor, SignedEvent, UnsignedEventInput } from "../src/protocol/index.ts";

type Extends<A, B> = A extends B ? true : false;
type Assert<T extends true> = T;

// Mutually assignable: the protocol shapes are the nostr shapes, field for field.
export type SignedIsEvent = Assert<Extends<SignedEvent, Event>>;
export type EventIsSigned = Assert<Extends<Event, SignedEvent>>;
export type RumorIsNip59 = Assert<Extends<Rumor, Nip59Rumor>>;
export type Nip59IsRumor = Assert<Extends<Nip59Rumor, Rumor>>;
// One direction only: the kernel input may omit pubkey (it fills the signing key's own), so
// UnsignedEventInput is wider than @qntx/nostr's UnsignedEvent.
export type UnsignedIsInput = Assert<Extends<UnsignedEvent, UnsignedEventInput>>;

describe("protocol event shapes", () => {
  it("match @qntx/nostr structurally (compile-time assertions above)", () => {
    expect(true).toBe(true);
  });
});
