/**
 * Factor plumbing for the host connector: public `UnlockFactor`/`InitialFactor` inputs become wire
 * `Factor` material, passkey material comes from the host's WebAuthn ceremony, and every secret
 * byte travels in a fresh exact-size buffer on the transfer list.
 */
import { base64urlnopad } from "@scure/base";

import type { Factor } from "./protocol/index.ts";
import { WalletError } from "./types.ts";
import type { FactorInfo, InitialFactor, PasskeyConfig, UnlockFactor } from "./types.ts";

export type PrfSalts = { readonly first: Uint8Array; readonly second?: Uint8Array };

/** Purpose bytes stamped into the first byte of a credential's WebAuthn user handle. */
export const PASSKEY_PURPOSE_WALLET = 0x01;
export const PASSKEY_PURPOSE_VAULT = 0x02;

export type PrfResult = {
  readonly credentialId: Uint8Array;
  readonly first: Uint8Array;
  readonly second?: Uint8Array;
  /** The assertion's `userHandle` — its first byte declares the credential's purpose. */
  readonly userHandle?: Uint8Array;
};

/**
 * The WebAuthn ceremony the host performs. Implementations throw `WalletError` — "cancelled" when
 * the user aborts, "factor-unavailable" when the credential cannot produce a PRF. `name` is the new
 * credential's display name, validated by the host before the call (1–64 characters).
 */
export type PasskeyCeremony = {
  readonly create: (input: {
    readonly purpose: "wallet" | "vault";
    readonly name: string;
    readonly salts: PrfSalts;
  }) => Promise<PrfResult>;
  readonly assert: (input: {
    readonly credentialIds?: ReadonlyArray<Uint8Array>;
    readonly salts: PrfSalts;
  }) => Promise<PrfResult>;
};

/** What factor resolution needs from the wallet: config, the ceremony, live factor records. */
export type FactorSource = {
  readonly passkey: PasskeyConfig;
  readonly ceremony: PasskeyCeremony | undefined;
  readonly factors: () => ReadonlyArray<FactorInfo>;
};

export function vaultSaltBytes(source: FactorSource): Uint8Array {
  return new TextEncoder().encode(source.passkey.vaultSalt);
}

export function walletSaltBytes(source: FactorSource): Uint8Array {
  return new TextEncoder().encode(source.passkey.walletSalt);
}

/** Passkey credential ids of the current vault factors, for `assert`'s allowCredentials. */
function passkeyCredentialIds(source: FactorSource): Uint8Array[] {
  return source
    .factors()
    .flatMap((factor) =>
      factor.kind === "passkey" ? [base64urlnopad.decode(factor.credentialId)] : [],
    );
}

/**
 * A Uint8Array is placed on the wire in a fresh exact-size buffer whose ArrayBuffer goes into the
 * transfer list — the bytes move to the kernel and cannot detach caller-owned memory. Secret
 * sources are wiped after copying.
 */
export function wireBytes(
  source: Uint8Array,
  transfer: ArrayBuffer[],
  wipeSource = false,
): Uint8Array {
  // Always a fresh exact-size buffer: transferring must never detach caller-owned memory.
  const wire = new Uint8Array(source);
  if (wipeSource) {
    source.fill(0);
  }
  transfer.push(wire.buffer);
  return wire;
}

export function wireSecretText(text: string, transfer: ArrayBuffer[]): Uint8Array {
  return wireBytes(new TextEncoder().encode(text), transfer);
}

export function requireCeremony(source: FactorSource): PasskeyCeremony {
  if (source.ceremony === undefined) {
    throw new WalletError("factor-unavailable", "no passkey ceremony is configured");
  }
  return source.ceremony;
}

/** A passkey credential's display name: trimmed, 1–64 UTF-16 code units, else invalid-input. */
export function passkeyName(name: string): string {
  const trimmed = name.trim();
  if (trimmed.length === 0 || trimmed.length > 64) {
    throw new WalletError("invalid-input", "the passkey name must be 1–64 characters");
  }
  return trimmed;
}

/**
 * Resolves a public `UnlockFactor` to wire factor material. `transfer` collects every buffer the
 * port must move. Ceremony errors surface as they are (cancelled / factor-unavailable).
 */
export async function resolveFactor(
  source: FactorSource,
  factor: UnlockFactor,
  transfer: ArrayBuffer[],
): Promise<Factor> {
  if (factor.kind === "password") {
    return { kind: "password", password: wireSecretText(factor.password, transfer) };
  }
  const ceremony = requireCeremony(source);
  const result = await ceremony.assert({
    credentialIds: passkeyCredentialIds(source),
    salts: { first: vaultSaltBytes(source) },
  });
  return {
    kind: "passkey",
    credentialId: wireBytes(result.credentialId, transfer),
    prf: wireBytes(result.first, transfer, true),
  };
}

/**
 * Resolves a public `InitialFactor` (a factor being created). For `create/restoreWithPasskey` the
 * default passkey factor reuses the wallet ceremony's own credential and `second` PRF output.
 */
export async function resolveInitialFactor(
  source: FactorSource,
  factor: InitialFactor | undefined,
  transfer: ArrayBuffer[],
  walletCeremony?: PrfResult,
): Promise<Factor> {
  if (factor === undefined || factor.kind === "passkey") {
    const name = factor === undefined ? undefined : passkeyName(factor.name);
    if (walletCeremony !== undefined) {
      const { second } = walletCeremony;
      if (second === undefined) {
        throw new WalletError("factor-unavailable", "the ceremony returned no vault PRF output");
      }
      return {
        kind: "passkey",
        credentialId: wireBytes(walletCeremony.credentialId, transfer),
        prf: wireBytes(second, transfer, true),
      };
    }
    if (name === undefined) {
      // No caller reaches this today (createFactorParam requires a factor), but the ceremony
      // contract needs a name — fail closed rather than inventing one.
      throw new WalletError("invalid-input", "a passkey factor requires a name");
    }
    const result = await requireCeremony(source).create({
      purpose: "vault",
      name,
      salts: { first: vaultSaltBytes(source) },
    });
    return {
      kind: "passkey",
      credentialId: wireBytes(result.credentialId, transfer),
      prf: wireBytes(result.first, transfer, true),
    };
  }
  if (factor.kind === "password") {
    walletCeremony?.second?.fill(0); // the passkey vault factor is not needed
    return { kind: "password", password: wireSecretText(factor.password, transfer) };
  }
  throw new WalletError("factor-unavailable", "hardware factors exist only on React Native");
}
