import { equalBytes } from "@noble/ciphers/utils.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import type { HDKey } from "@scure/bip32";

import type { Factor, NullValue } from "@qntx/wallet/protocol";
import type { WalletInfo } from "@qntx/wallet/types";

import { masterKey } from "../derive/hd.ts";
import { walletIdOf } from "../derive/wallet-id.ts";
import { KernelError } from "../errors.ts";
import type { KernelPlatform } from "../platform.ts";
import { decodeUtf8Secret, Secret, wipe } from "../secret/secret.ts";
import { randomEntropy } from "../seed/entropy.ts";
import { entropyFromMnemonic, mnemonicFromEntropy } from "../seed/mnemonic.ts";
import { entropyFromPrf } from "../seed/passkey.ts";
import { seedFromEntropy } from "../seed/seed.ts";
import type { PendingFactor } from "../session/session.ts";
import { wrapDek } from "../vault/factors.ts";
import { encodeHeader } from "../vault/headers.ts";
import type { EntropyHeader } from "../vault/headers.ts";
import type { StoredFactor, StoredRecord } from "../vault/store.ts";
import {
  establishOps,
  factorHeader,
  findRecord,
  makeFactor,
  newFactorKek,
  sealRecord,
  verifyFactor,
  walletInfo,
} from "../vault/vault.ts";
import type { KernelContext } from "./context.ts";

async function deriveWalletMaterial(
  platform: KernelPlatform,
  entropy: Uint8Array,
): Promise<{ master: HDKey; walletId: string }> {
  const seed = await seedFromEntropy(entropy, platform.pbkdf2);
  try {
    const master = masterKey(seed);
    return { master, walletId: walletIdOf(master) };
  } finally {
    wipe(seed);
  }
}

type WalletMaterial = {
  readonly walletId: string;
  readonly entropy: Uint8Array;
  readonly words: EntropyHeader["words"];
  readonly origin: EntropyHeader["origin"];
};

/** Entropy → master → walletId. `entropy` is not consumed. */
async function walletMaterial(
  platform: KernelPlatform,
  entropy: Uint8Array,
  origin: EntropyHeader["origin"],
  words: EntropyHeader["words"],
): Promise<WalletMaterial> {
  const { master, walletId } = await deriveWalletMaterial(platform, entropy);
  try {
    return { walletId, entropy, words, origin };
  } finally {
    master.wipePrivateData();
  }
}

function walletInfoOf(material: WalletMaterial, backedUp: boolean, createdAt: number): WalletInfo {
  return walletInfo({
    walletId: material.walletId,
    origin: material.origin,
    words: material.words,
    backedUp,
    createdAt,
  });
}

/** The entropy record for a new wallet, sealed under `dek`. Consumes nothing. */
function walletRecord(
  ctx: KernelContext,
  dek: Secret,
  material: WalletMaterial,
  backedUp: boolean,
  createdAt: number,
): StoredRecord {
  const header = encodeHeader({
    walletId: material.walletId,
    origin: material.origin,
    words: material.words,
    backedUp,
    createdAt,
  });
  return sealRecord(
    ctx.platform,
    dek,
    "entropy",
    material.walletId,
    header,
    new Uint8Array(material.entropy),
  );
}

/**
 * The dynamic gate on every "create or import" command: with an uninitialized vault `factor` is
 * required and the command must commit through `expect-uninitialized`; with an established vault
 * `factor` must be absent and the request must carry the live session.
 */
export function gate(
  ctx: KernelContext,
  factor: Factor | undefined,
  requestSession: string | undefined,
): { readonly uninitialized: boolean; readonly dek: Secret } {
  if (ctx.image.meta === undefined) {
    if (factor === undefined) {
      throw new KernelError("invalid-input", "an initial factor is required");
    }
    return { uninitialized: true, dek: Secret.take(ctx.platform.random(32)) };
  }
  if (factor !== undefined) {
    throw new KernelError("invalid-input", "vault is already initialized");
  }
  const session = ctx.session.require(requestSession);
  return { uninitialized: false, dek: session.dek };
}

/**
 * Commits a create/import command. On the uninitialized path the vault (meta + factor + records) is
 * established in ONE commit guarded by `expect-uninitialized`; a racing establish makes the commit
 * fail with `integrity` and nothing is written. On the initialized path only the records are
 * appended under the live session DEK. Returns the session id.
 */
export async function commitRecords(
  ctx: KernelContext,
  gated: { readonly uninitialized: boolean; readonly dek: Secret },
  factor: Factor | undefined,
  records: StoredRecord[],
): Promise<string> {
  if (gated.uninitialized) {
    if (factor === undefined) {
      throw new KernelError("integrity", "unreachable: initial factor missing");
    }
    const storedFactor = await makeFactor(ctx.platform, factor, gated.dek);
    try {
      await ctx.commit([...establishOps(storedFactor, records)]);
    } catch (error) {
      gated.dek.wipe();
      throw error;
    }
    return ctx.session.open(gated.dek);
  }
  await ctx.commit(records.map((record) => ({ op: "put-record" as const, record })));
  return ctx.session.current().id;
}

function ensureNewWallet(ctx: KernelContext, material: WalletMaterial): void {
  if (ctx.image.records.some((r) => r.kind === "entropy" && r.id === material.walletId)) {
    throw new KernelError("already-exists", "wallet already exists");
  }
}

/** Three distinct quiz positions via rejection sampling on whole bytes. */
function quizPositions(random: KernelPlatform["random"], count: number): [number, number, number] {
  const limit = 256 - (256 % count);
  const picked = new Set<number>();
  while (picked.size < 3) {
    const draw = random(4);
    for (let i = 0; i < 4 && picked.size < 3; i++) {
      const b = draw[i];
      if (b !== undefined && b < limit) {
        picked.add(b % count);
      }
    }
  }
  const [a, b, c] = [...picked];
  return [a ?? 0, b ?? 0, c ?? 0];
}

/**
 * Factor material for an uninitialized-vault `createMnemonic`: the KEK is derived now (600k PBKDF2
 * must not run twice) and held in the draft until confirm/discard/lock. The password policy applies
 * inside `newFactorKek` because the factor is being created.
 */
async function pendingFactorOf(ctx: KernelContext, factor: Factor): Promise<PendingFactor> {
  const material = await newFactorKek(ctx.platform, factor);
  return material.kind === "password"
    ? { kind: "password", kek: Secret.take(material.kek), salt: material.salt }
    : { kind: "passkey", kek: Secret.take(material.kek), credentialId: material.credentialId };
}

export async function createMnemonic(
  ctx: KernelContext,
  params: { words: 12 | 24; factor?: Factor },
  requestSession: string | undefined,
): Promise<{ draft: string; words: Uint8Array; quiz: ReadonlyArray<number> }> {
  const uninitialized = ctx.image.meta === undefined;
  let pendingFactor: PendingFactor | undefined;
  if (uninitialized) {
    if (params.factor === undefined) {
      throw new KernelError("invalid-input", "an initial factor is required");
    }
    pendingFactor = await pendingFactorOf(ctx, params.factor);
  } else {
    if (params.factor !== undefined) {
      throw new KernelError("invalid-input", "vault is already initialized");
    }
    ctx.session.require(requestSession);
  }
  const entropy = randomEntropy(params.words, ctx.platform.random);
  const mnemonic = mnemonicFromEntropy(entropy);
  const wordList = mnemonic.split(" ");
  const quiz = quizPositions(ctx.platform.random, wordList.length);
  const expected = quiz.map((position) => utf8ToBytes(wordList[position] ?? ""));
  const id = bytesToHex(ctx.platform.random(16));
  ctx.session.putDraft(id, {
    entropy: Secret.take(entropy),
    words: params.words,
    quiz,
    expected,
    pendingFactor,
  });
  return { draft: id, words: utf8ToBytes(mnemonic), quiz };
}

/** Turns a draft's pending factor into its stored record once the DEK exists. */
function storedFactorForPending(
  ctx: KernelContext,
  pending: PendingFactor,
  dek: Secret,
): StoredFactor {
  const id = bytesToHex(ctx.platform.random(16));
  const header = factorHeader(pending, ctx.platform.now());
  const sealed = pending.kek.use((kek) =>
    wrapDek(kek, dek, { kind: pending.kind, id, header }, ctx.platform.random),
  );
  return { kind: pending.kind, id, header, sealed };
}

export async function confirmMnemonic(
  ctx: KernelContext,
  params: { draft: string; answers: ReadonlyArray<Uint8Array> },
): Promise<{ wallet: WalletInfo; session: string }> {
  const draft = ctx.session.getDraft(params.draft);
  const allMatch = draft.expected.every((expected, i) => {
    const answer = params.answers[i];
    return (
      answer !== undefined && answer.length === expected.length && equalBytes(answer, expected)
    );
  });
  for (const answer of params.answers) {
    wipe(answer);
  }
  if (!allMatch) {
    // Wrong answers keep the draft so the user can try again.
    throw new KernelError("invalid-input", "backup confirmation failed");
  }
  const taken = ctx.session.takeDraft(params.draft);
  try {
    const entropy = taken.entropy.use((bytes) => new Uint8Array(bytes));
    const material = await walletMaterial(ctx.platform, entropy, "mnemonic", taken.words);
    try {
      ensureNewWallet(ctx, material);
      const createdAt = ctx.platform.now();
      // The quiz just proved the user wrote the words down.
      if (taken.pendingFactor !== undefined) {
        const dek = Secret.take(ctx.platform.random(32));
        const storedFactor = storedFactorForPending(ctx, taken.pendingFactor, dek);
        const record = walletRecord(ctx, dek, material, true, createdAt);
        try {
          await ctx.commit(establishOps(storedFactor, [record]));
        } catch (error) {
          dek.wipe();
          throw error;
        }
        const session = ctx.session.open(dek);
        return { wallet: walletInfoOf(material, true, createdAt), session };
      }
      const session = ctx.session.current();
      const record = walletRecord(ctx, session.dek, material, true, createdAt);
      await ctx.commit([{ op: "put-record", record }]);
      return { wallet: walletInfoOf(material, true, createdAt), session: session.id };
    } finally {
      wipe(entropy);
    }
  } finally {
    taken.entropy.wipe();
    for (const expected of taken.expected) {
      wipe(expected);
    }
    if (taken.pendingFactor !== undefined) {
      taken.pendingFactor.kek.wipe();
      if (taken.pendingFactor.kind === "password") {
        wipe(taken.pendingFactor.salt);
      } else {
        wipe(taken.pendingFactor.credentialId);
      }
    }
  }
}

export function discardMnemonic(ctx: KernelContext, params: { draft: string }): NullValue {
  ctx.session.dropDraft(params.draft);
  return null;
}

function mnemonicWords(entropy: Uint8Array): EntropyHeader["words"] {
  const words = (entropy.length / 4) * 3;
  if (words !== 12 && words !== 15 && words !== 18 && words !== 21 && words !== 24) {
    throw new KernelError("integrity", "invalid entropy length");
  }
  return words;
}

export async function importMnemonic(
  ctx: KernelContext,
  params: { mnemonic: Uint8Array; factor?: Factor },
  requestSession: string | undefined,
): Promise<{ wallet: WalletInfo; session: string }> {
  const gated = gate(ctx, params.factor, requestSession);
  const text = decodeUtf8Secret(params.mnemonic); // wipes `params.mnemonic`
  const entropy = entropyFromMnemonic(text);
  const material = await walletMaterial(ctx.platform, entropy, "mnemonic", mnemonicWords(entropy));
  try {
    ensureNewWallet(ctx, material);
    const createdAt = ctx.platform.now();
    // An imported mnemonic is already written down somewhere: backedUp is true.
    const record = walletRecord(ctx, gated.dek, material, true, createdAt);
    const session = await commitRecords(ctx, gated, params.factor, [record]);
    return { wallet: walletInfoOf(material, true, createdAt), session };
  } finally {
    wipe(entropy);
  }
}

export async function createWithPasskey(
  ctx: KernelContext,
  params: { credentialId: Uint8Array; prfWallet: Uint8Array; factor?: Factor },
  requestSession: string | undefined,
): Promise<{ wallet: WalletInfo; session: string }> {
  const gated = gate(ctx, params.factor, requestSession);
  const entropy = entropyFromPrf(params.prfWallet);
  const material = await walletMaterial(ctx.platform, entropy, "passkey", 12);
  try {
    ensureNewWallet(ctx, material);
    const createdAt = ctx.platform.now();
    // Passkey wallets are backed up by definition: the credential is synced by the platform's
    // password manager and the entropy is re-derivable.
    const record = walletRecord(ctx, gated.dek, material, true, createdAt);
    const session = await commitRecords(ctx, gated, params.factor, [record]);
    return { wallet: walletInfoOf(material, true, createdAt), session };
  } finally {
    wipe(entropy);
  }
}

export async function deleteWallet(
  ctx: KernelContext,
  params: { verify: Factor; walletId: string },
  requestSession: string | undefined,
): Promise<NullValue> {
  const { dek } = ctx.session.require(requestSession);
  await verifyFactor(ctx.platform, ctx.image, params.verify, dek);
  findRecord(ctx.image, "entropy", params.walletId);
  // The entropy row and every module record derived from this wallet go in ONE commit —
  // a partial deletion can never land.
  const extras = ctx.modules.map((module) => module.walletDeleteOps(ctx.image, params.walletId));
  await ctx.commit([
    { op: "delete-record", kind: "entropy", id: params.walletId },
    ...extras.flatMap((extra) => extra.ops),
  ]);
  for (const extra of extras) {
    extra.after();
  }
  return null;
}
