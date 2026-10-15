import type { Factor, NullValue } from "@qntx/wallet/protocol";
import type { FactorInfo } from "@qntx/wallet/types";

import { KernelError } from "../errors.ts";
import type { StoreOp } from "../vault/store.ts";
import { factorInfo, makeFactor, unlock, verifyFactor } from "../vault/vault.ts";
import type { KernelContext } from "./context.ts";

export async function unlockVault(
  ctx: KernelContext,
  params: { factor: Factor },
): Promise<{ session: string }> {
  const { dek, nostrKeys } = await unlock(ctx.platform, ctx.image, params.factor);
  try {
    ctx.pool.dispose();
    for (const secretKey of nostrKeys.values()) {
      ctx.pool.add(secretKey); // takes ownership and wipes the record plaintext
    }
    nostrKeys.clear();
    return { session: ctx.session.open(dek) };
  } catch (error) {
    for (const secretKey of nostrKeys.values()) {
      secretKey.fill(0);
    }
    dek.wipe();
    throw error;
  }
}

export function lockVault(ctx: KernelContext): NullValue {
  ctx.session.lock("user");
  return null;
}

export async function resetVault(ctx: KernelContext): Promise<NullValue> {
  await ctx.commit([{ op: "clear" }]); // commit itself drops the session to uninitialized
  return null;
}

/**
 * Adds a factor after re-verifying with an existing one. A password factor REPLACES the existing
 * password factor in one commit (the vault holds at most one) — that is "change password". At least
 * one factor always remains: the replacement happens atomically.
 */
export async function addFactor(
  ctx: KernelContext,
  params: { verify: Factor; factor: Factor },
  requestSession: string | undefined,
): Promise<FactorInfo> {
  const { dek } = ctx.session.require(requestSession);
  await verifyFactor(ctx.platform, ctx.image, params.verify, dek);
  const stored = await makeFactor(ctx.platform, params.factor, dek);
  const replaced =
    params.factor.kind === "password"
      ? ctx.image.factors.find((f) => f.kind === "password")
      : undefined;
  const ops: StoreOp[] = [
    ...(replaced === undefined ? [] : [{ op: "delete-factor" as const, id: replaced.id }]),
    { op: "put-factor", factor: stored },
  ];
  await ctx.commit(ops);
  return factorInfo(stored);
}

export async function removeFactor(
  ctx: KernelContext,
  params: { verify: Factor; id: string },
  requestSession: string | undefined,
): Promise<NullValue> {
  const { dek } = ctx.session.require(requestSession);
  await verifyFactor(ctx.platform, ctx.image, params.verify, dek);
  const stored = ctx.image.factors.find((f) => f.id === params.id);
  if (stored === undefined) {
    throw new KernelError("not-found", "no such factor");
  }
  if (ctx.image.factors.length <= 1) {
    throw new KernelError("invalid-input", "the vault must keep at least one factor");
  }
  await ctx.commit([{ op: "delete-factor", id: params.id }]);
  return null;
}
