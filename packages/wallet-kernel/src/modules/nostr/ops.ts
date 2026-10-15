import type { Event } from "@qntx/nostr";
import type { SignedEvent, UnsignedEventInput, UnwrapResult } from "@qntx/wallet/protocol";

import type { KernelContext } from "../../commands/context.ts";
import type { SignerPool } from "./pool.ts";
import { signEvent, unwrapGiftWrap } from "./pool.ts";

export async function sign(
  ctx: KernelContext,
  pool: SignerPool,
  params: { publicKey: string; event: UnsignedEventInput },
  requestSession: string | undefined,
): Promise<SignedEvent> {
  ctx.session.require(requestSession);
  return signEvent(pool, params.publicKey, params.event);
}

export async function nip04Encrypt(
  ctx: KernelContext,
  pool: SignerPool,
  params: { publicKey: string; peer: string; text: string },
  requestSession: string | undefined,
): Promise<string> {
  ctx.session.require(requestSession);
  return pool.get(params.publicKey).nip04Encrypt(params.peer, params.text);
}

export async function nip04Decrypt(
  ctx: KernelContext,
  pool: SignerPool,
  params: { publicKey: string; peer: string; text: string },
  requestSession: string | undefined,
): Promise<string> {
  ctx.session.require(requestSession);
  return pool.get(params.publicKey).nip04Decrypt(params.peer, params.text);
}

export async function nip44Encrypt(
  ctx: KernelContext,
  pool: SignerPool,
  params: { publicKey: string; peer: string; text: string },
  requestSession: string | undefined,
): Promise<string> {
  ctx.session.require(requestSession);
  return pool.get(params.publicKey).nip44Encrypt(params.peer, params.text);
}

export async function nip44Decrypt(
  ctx: KernelContext,
  pool: SignerPool,
  params: { publicKey: string; peer: string; text: string },
  requestSession: string | undefined,
): Promise<string> {
  ctx.session.require(requestSession);
  return pool.get(params.publicKey).nip44Decrypt(params.peer, params.text);
}

export async function unwrapGiftWraps(
  ctx: KernelContext,
  pool: SignerPool,
  params: { publicKey: string; events: ReadonlyArray<Event> },
  requestSession: string | undefined,
): Promise<{ results: ReadonlyArray<UnwrapResult> }> {
  ctx.session.require(requestSession);
  const results: UnwrapResult[] = [];
  for (const event of params.events) {
    // oxlint-disable-next-line eslint/no-await-in-loop -- batch results are produced in order, one wrap at a time
    results.push(await unwrapGiftWrap(pool, params.publicKey, event));
  }
  return { results };
}
