import type { Factor, NullValue } from "@qntx/wallet/protocol";
import type { FactorInfo } from "@qntx/wallet/types";

import { KernelError } from "../errors.ts";
import type { Secret } from "../secret/secret.ts";
import type { VaultImage } from "../vault/store.ts";
import { factorInfo, makeFactor, rotateVault, unlock, verifyFactor } from "../vault/vault.ts";
import type { KernelContext } from "./context.ts";

const EMPTY_IMAGE: VaultImage = { meta: undefined, records: [], factors: [] };

export async function unlockVault(
  ctx: KernelContext,
  params: { factor: Factor },
): Promise<{ session: string }> {
  // The attempt must see the freshest counters and factor set — not the cached image. If the
  // reload surfaces a non-ok health (data this build rejects), the unlock must not run.
  await ctx.reload();
  if (ctx.health === "corrupted") {
    throw new KernelError("integrity", "the vault is corrupted");
  }
  if (ctx.health === "unsupported") {
    throw new KernelError("unsupported", "the vault needs a newer build");
  }
  const { dek, keyId } = await unlock(ctx.platform, ctx.image, params.factor, ctx.commit);
  return { session: openSession(ctx, dek, keyId) };
}

/**
 * Opens a session over `ctx.image` and rebuilds live state in one pass: every module drops stale
 * state, then the whole image reconciles in from empty — every record opens under the DEK and every
 * factor binding verifies. A failure latches corrupted and invalidates the session it just opened.
 * Shared by `vault.unlock` and the establish paths that open a session on commit.
 */
export function openSession(ctx: KernelContext, dek: Secret, keyId: string): string {
  for (const module of ctx.modules) {
    module.lock();
  }
  const session = ctx.session.open(dek, keyId);
  ctx.reconcile(EMPTY_IMAGE);
  if (!ctx.session.unlocked) {
    throw new KernelError("integrity", "vault contents failed authentication", undefined, true);
  }
  return session;
}

export async function resetVault(ctx: KernelContext): Promise<NullValue> {
  // A user-initiated reset locks with "user" before the commit drops the session to
  // uninitialized — an external wipe reaching setInitialized instead reports "invalidated".
  ctx.session.lock("user");
  await ctx.commit([{ op: "clear" }]);
  return null;
}

/**
 * Adds a factor after re-verifying with an existing one. A password factor REPLACES the existing
 * password factor and rotates the DEK (change password): every record re-seals and every retained
 * factor re-wraps in one guarded commit — other hosts see the keyId change and invalidate. A
 * passkey factor wraps the current DEK only: no rotation, keyId unchanged. At least one factor
 * always remains.
 */
export async function addFactor(
  ctx: KernelContext,
  params: { verify: Factor; factor: Factor },
  requestSession: string | undefined,
): Promise<FactorInfo> {
  const { dek } = ctx.session.require(requestSession);
  await verifyFactor(ctx.platform, ctx.image, params.verify, dek);
  if (params.factor.kind === "passkey") {
    const stored = await makeFactor(ctx.platform, params.factor, dek);
    await ctx.commit([{ op: "put-factor", factor: stored }]);
    return factorInfo(stored);
  }
  const replaced = ctx.image.factors.find((f) => f.kind === "password");
  const rotation = await rotateVault(
    ctx.platform,
    ctx.image,
    dek,
    new Set(replaced === undefined ? [] : [replaced.id]),
    [params.factor],
  );
  const addedRow = rotation.added.at(0);
  if (addedRow === undefined) {
    throw new KernelError("integrity", "unreachable: rotation produced no factor");
  }
  const info = factorInfo(addedRow);
  await ctx.commit(rotation.ops, {
    rotate: { dek: rotation.dek, keyId: rotation.keyId },
  });
  return info;
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
  const rotation = await rotateVault(ctx.platform, ctx.image, dek, new Set([params.id]), []);
  await ctx.commit(rotation.ops, {
    rotate: { dek: rotation.dek, keyId: rotation.keyId },
  });
  return null;
}
