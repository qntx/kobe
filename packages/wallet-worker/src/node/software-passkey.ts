/**
 * CreateSoftwarePasskey — a TEST-ONLY PasskeyCeremony. There is no authenticator, no user presence
 * check, no credential store: the "passkey" is a deterministic function of `seed`, so anyone
 * holding the seed owns every wallet it ever protects. Use it in tests and demos only.
 *
 * CredentialId = SHA-256(seed ‖ "credential" ‖ u32be(n)) (n increments per create) PRF(salt) =
 * HMAC-SHA256(HMAC-SHA256(seed, credentialId), SHA-256(UTF-8("WebAuthn PRF") ‖ 0x00 ‖ salt))
 * UserHandle = purpose byte ‖ SHA-256(seed ‖ "user-handle" ‖ credentialId)[0:15] — the same
 * 16-byte, purpose-prefixed shape the browser create path puts in `user.id`.
 */
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";

import { WalletError } from "@qntx/wallet";
import { PASSKEY_PURPOSE_VAULT, PASSKEY_PURPOSE_WALLET } from "@qntx/wallet/host";
import type { PasskeyCeremony, PrfResult, PrfSalts } from "@qntx/wallet/host";

export function createSoftwarePasskey(
  seed: Uint8Array,
  options?: { readonly synced?: boolean },
): PasskeyCeremony {
  const synced = options?.synced ?? true; // software credentials pretend to be synced by default
  let counter = 0;
  let lastCreated: Uint8Array | undefined;
  const known = new Map<string, { credentialId: Uint8Array; userHandle: Uint8Array }>();

  const prf = (credentialId: Uint8Array, salt: Uint8Array): Uint8Array => {
    const key = hmac(sha256, seed, credentialId);
    const message = sha256(concatBytes(utf8ToBytes("WebAuthn PRF"), new Uint8Array([0]), salt));
    return hmac(sha256, key, message);
  };

  const result = (
    credentialId: Uint8Array,
    salts: PrfSalts,
    userHandle?: Uint8Array,
  ): PrfResult => ({
    credentialId: new Uint8Array(credentialId),
    first: prf(credentialId, salts.first),
    ...(salts.second === undefined ? {} : { second: prf(credentialId, salts.second) }),
    ...(userHandle === undefined ? {} : { userHandle: new Uint8Array(userHandle) }),
    synced,
  });

  return {
    // oxlint-disable-next-line typescript/require-await -- the ceremony contract is async; this test double computes synchronously
    create: async ({ purpose, salts }) => {
      const counterBytes = new Uint8Array(4);
      new DataView(counterBytes.buffer).setUint32(0, counter);
      counter++;
      const credentialId = sha256(concatBytes(seed, utf8ToBytes("credential"), counterBytes));
      const purposeByte = purpose === "wallet" ? PASSKEY_PURPOSE_WALLET : PASSKEY_PURPOSE_VAULT;
      const userHandle = new Uint8Array(16);
      userHandle[0] = purposeByte;
      userHandle.set(
        sha256(concatBytes(seed, utf8ToBytes("user-handle"), credentialId)).subarray(0, 15),
        1,
      );
      known.set(bytesToHex(credentialId), { credentialId, userHandle });
      lastCreated = credentialId;
      return result(credentialId, salts);
    },
    // oxlint-disable-next-line typescript/require-await -- the ceremony contract is async; this test double computes synchronously
    assert: async ({ credentialIds, salts }) => {
      const credentialId =
        credentialIds === undefined
          ? lastCreated
          : credentialIds.find((id) => known.has(bytesToHex(id)));
      if (credentialId === undefined) {
        throw new WalletError(
          "factor-unavailable",
          credentialIds === undefined
            ? "no software credential exists yet"
            : "unknown software credential",
        );
      }
      const entry = known.get(bytesToHex(credentialId));
      return result(credentialId, salts, entry?.userHandle);
    },
  };
}
