/**
 * The WebAuthn passkey ceremony (main thread only): `navigator.credentials` with the PRF extension.
 * A wallet passkey derives the wallet seed from `PRF(walletSalt)`; the vault factor derives the
 * vault KEK from `PRF(vaultSalt)` on the same credential. Every ceremony output is checked for
 * `prf.enabled`, PRF results and the user-verification flag — a credential that cannot prove UV
 * never reaches the kernel.
 */
import { WalletError } from "@qntx/wallet";
import { PASSKEY_PURPOSE_VAULT, PASSKEY_PURPOSE_WALLET } from "@qntx/wallet/host";
import type { PasskeyCeremony, PrfResult, PrfSalts } from "@qntx/wallet/host";

export type WebAuthnRp = {
  /** RP id — the origin's effective domain, e.g. `location.hostname`. */
  readonly id: string;
  readonly name: string;
};

const UV_FLAG = 0x04; // authenticator-data flags byte (offset 32), bit 2 = user verified
const BE_FLAG = 0x08; // bit 3 = credential is backup-eligible (multi-device capable)
const BS_FLAG = 0x10; // bit 4 = credential is currently backed up (synced)

function factorUnavailable(message: string): WalletError {
  return new WalletError("factor-unavailable", message);
}

function cancelled(message: string): WalletError {
  return new WalletError("cancelled", message);
}

function mapCeremonyError(error: unknown): never {
  if (
    error instanceof DOMException &&
    (error.name === "NotAllowedError" || error.name === "AbortError")
  ) {
    throw cancelled("the passkey ceremony was cancelled");
  }
  if (error instanceof WalletError) {
    throw error;
  }
  throw factorUnavailable("the passkey ceremony failed");
}

/** The UV bit of an authenticator-data blob (flags byte at offset 32, bit 0x04). */
function userVerified(authenticatorData: ArrayBuffer): boolean {
  return (
    authenticatorData.byteLength > 32 &&
    // oxlint-disable-next-line eslint/no-bitwise -- flags bit test
    (new DataView(authenticatorData).getUint8(32) & UV_FLAG) !== 0
  );
}

/**
 * Whether the credential is backed up off-device (flags byte at offset 32): synced requires both BE
 * (the credential is eligible for backup) and BS (the authenticator actually backs it up).
 */
function credentialSynced(authenticatorData: ArrayBuffer): boolean {
  return (
    authenticatorData.byteLength > 32 &&
    // oxlint-disable-next-line eslint/no-bitwise -- flags bit test
    (new DataView(authenticatorData).getUint8(32) & (BE_FLAG | BS_FLAG)) === (BE_FLAG | BS_FLAG)
  );
}

function prfEval(salts: PrfSalts): AuthenticationExtensionsPRFValues {
  // The constructor copy narrows Uint8Array<ArrayBufferLike> to Uint8Array<ArrayBuffer> —
  // the DOM BufferSource does not admit shared-array-buffer views.
  return salts.second === undefined
    ? { first: new Uint8Array(salts.first) }
    : { first: new Uint8Array(salts.first), second: new Uint8Array(salts.second) };
}

/** A detached copy of a BufferSource — the returned Uint8Array owns its own fresh buffer. */
function copyBufferSource(source: BufferSource): Uint8Array {
  const view =
    source instanceof ArrayBuffer
      ? new Uint8Array(source)
      : new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
  return new Uint8Array(view);
}

function readPrfResult(
  credential: PublicKeyCredential,
  results: AuthenticationExtensionsPRFValues | undefined,
  wantSecond: boolean,
  synced: boolean,
  userHandle?: ArrayBuffer,
): PrfResult {
  const first = results?.first;
  const second = results?.second;
  if (first === undefined || (wantSecond && second === undefined)) {
    throw factorUnavailable("the passkey produced no PRF output");
  }
  // Copy into fresh Uint8Arrays and drop every reference to the extension's ArrayBuffers.
  return {
    credentialId: copyBufferSource(credential.rawId),
    first: copyBufferSource(first),
    ...(second === undefined ? {} : { second: copyBufferSource(second) }),
    ...(userHandle === undefined ? {} : { userHandle: copyBufferSource(userHandle) }),
    synced,
  };
}

function checkCredential(credential: unknown): PublicKeyCredential {
  if (!(credential instanceof PublicKeyCredential)) {
    throw factorUnavailable("the authenticator returned no public-key credential");
  }
  return credential;
}

/**
 * The WebAuthn ceremony. `create` registers a resident credential with `prf.eval` over the salts;
 * when the extension returns no results a single assertion over the new credential produces them.
 * `assert` runs a discoverable (or allowCredentials-scoped) get with the same eval shape.
 */
export function createWebAuthnPasskey(rp: WebAuthnRp): PasskeyCeremony {
  async function assert(input: {
    readonly credentialIds?: ReadonlyArray<Uint8Array>;
    readonly salts: PrfSalts;
  }): Promise<PrfResult> {
    let credential: PublicKeyCredential;
    try {
      credential = checkCredential(
        await navigator.credentials.get({
          publicKey: {
            rpId: rp.id,
            challenge: crypto.getRandomValues(new Uint8Array(32)),
            userVerification: "required",
            ...(input.credentialIds === undefined
              ? {}
              : {
                  allowCredentials: input.credentialIds.map((id) => ({
                    type: "public-key" as const,
                    id: new Uint8Array(id),
                  })),
                }),
            extensions: { prf: { eval: prfEval(input.salts) } },
          },
        }),
      );
    } catch (error) {
      mapCeremonyError(error);
    }
    const { response } = credential;
    if (!(response instanceof AuthenticatorAssertionResponse)) {
      throw factorUnavailable("the authenticator returned no assertion response");
    }
    if (!userVerified(response.authenticatorData)) {
      throw factorUnavailable("the passkey assertion was not user-verified");
    }
    return readPrfResult(
      credential,
      credential.getClientExtensionResults().prf?.results,
      input.salts.second !== undefined,
      credentialSynced(response.authenticatorData),
      response.userHandle ?? undefined,
    );
  }

  return {
    create: async (input) => {
      const userId = new Uint8Array(16);
      userId[0] = input.purpose === "wallet" ? PASSKEY_PURPOSE_WALLET : PASSKEY_PURPOSE_VAULT;
      crypto.getRandomValues(userId.subarray(1));
      let credential: PublicKeyCredential;
      try {
        credential = checkCredential(
          await navigator.credentials.create({
            publicKey: {
              rp: { id: rp.id, name: rp.name },
              user: {
                id: userId,
                name: input.name,
                displayName: input.name,
              },
              challenge: crypto.getRandomValues(new Uint8Array(32)),
              pubKeyCredParams: [
                { type: "public-key", alg: -7 },
                { type: "public-key", alg: -257 },
              ],
              authenticatorSelection: {
                residentKey: "required",
                userVerification: "required",
              },
              extensions: { prf: { eval: prfEval(input.salts) } },
            },
          }),
        );
      } catch (error) {
        mapCeremonyError(error);
      }
      const { response } = credential;
      if (!(response instanceof AuthenticatorAttestationResponse)) {
        throw factorUnavailable("the authenticator returned no attestation response");
      }
      const extensions = credential.getClientExtensionResults();
      if (extensions.prf?.enabled !== true) {
        throw factorUnavailable("the authenticator does not support the PRF extension");
      }
      if (extensions.prf.results === undefined) {
        // Some authenticators omit creation-time PRF outputs: one assertion over the new
        // credential produces them (it is that response whose UV and BE/BS flags get read).
        return assert({
          credentialIds: [copyBufferSource(credential.rawId)],
          salts: input.salts,
        });
      }
      const authenticatorData = response.getAuthenticatorData();
      if (!userVerified(authenticatorData)) {
        throw factorUnavailable("the passkey creation was not user-verified");
      }
      return readPrfResult(
        credential,
        extensions.prf.results,
        input.salts.second !== undefined,
        credentialSynced(authenticatorData),
      );
    },
    assert,
  };
}
