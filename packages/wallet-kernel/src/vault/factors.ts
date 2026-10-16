import { equalBytes } from "@noble/ciphers/utils.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { base64urlnopad } from "@scure/base";

import { KernelError } from "../errors.ts";
import type { Pbkdf2, Random } from "../platform.ts";
import { Secret, decodeUtf8Secret, wipe } from "../secret/secret.ts";
import { aadOf, factorContext, open, seal } from "./envelope.ts";
import { parsePasskeyFactorHeader, parsePasswordFactorHeader } from "./headers.ts";
import type { StoredFactor } from "./store.ts";

const PASSWORD_ITERATIONS = 600000;

/**
 * Factor wrapping v2: each factor carries a static X25519 key pair derived from its KEK; the public
 * half lives in the factor's header so a DEK can be wrapped to a factor without knowing its KEK.
 *
 * FactorSk = HKDF-SHA256(ikm = KEK, salt = empty, info = "qntx-wallet/vault/v2/factor-key", 32)
 *
 * FactorPk = X25519(factorSk)
 *
 * WrapKey = HKDF-SHA256(ikm = X25519(eph, factorPk), salt = ephPk ‖ factorPk, info =
 * "qntx-wallet/vault/v2/wrap", 32)
 *
 * Binding = HMAC-SHA256(key = DEK, msg = UTF-8("qntx-wallet/vault/v2/binding") ‖ aad)
 *
 * Sealed = 0x02 ‖ ephPk(32) ‖ binding(32) ‖ envelopeV1Seal(wrapKey, DEK, factorContext, header)
 *
 * The binding tag authenticates the wrapped DEK against the factor's public material — a row whose
 * DEK is not this vault's, or whose header was altered, fails the check.
 */
const FACTOR_KEY_INFO = utf8ToBytes("qntx-wallet/vault/v2/factor-key");
const WRAP_INFO = utf8ToBytes("qntx-wallet/vault/v2/wrap");
const BINDING_TAG = utf8ToBytes("qntx-wallet/vault/v2/binding");
const WRAP_VERSION = 0x02;
const ZERO32 = new Uint8Array(32);
// 0x02 ‖ ephPk ‖ binding ‖ envelopeV1(0x01 ‖ nonce(24) ‖ tag(16)) over a 32-byte DEK.
const WRAPPED_DEK_LENGTH = 1 + 32 + 32 + 1 + 24 + 16 + 32;

function decodePassword(password: Uint8Array): string {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(password);
  } catch {
    throw new KernelError("invalid-input", "password is not valid UTF-8");
  }
  return text.normalize("NFKC");
}

/**
 * Policy for a password factor at creation time: at least 10 Unicode code points after NFKC. Never
 * applied at unlock — a failing password there is just a wrong-password attempt.
 */
export function assertPasswordPolicy(password: Uint8Array): void {
  // oxlint-disable-next-line typescript/no-misused-spread -- counts Unicode code points of the NFKC password
  if ([...decodePassword(password)].length < 10) {
    throw new KernelError("invalid-input", "password must be at least 10 characters");
  }
}

/**
 * Password factor KEK: PBKDF2-HMAC-SHA256(UTF-8(NFKC(password)), salt, 600000, 32). The password
 * arrives as UTF-8 bytes (protocol rule) and is wiped afterwards.
 */
export async function passwordKek(
  password: Uint8Array,
  salt: Uint8Array,
  pbkdf2: Pbkdf2,
): Promise<Uint8Array> {
  const normalized = decodeUtf8Secret(password).normalize("NFKC"); // wipes `password`
  const normalizedBytes = utf8ToBytes(normalized);
  try {
    return await pbkdf2("sha256", normalizedBytes, salt, PASSWORD_ITERATIONS, 32);
  } finally {
    wipe(normalizedBytes);
  }
}

/**
 * Passkey factor KEK: HKDF-SHA256(ikm = prf, salt = credentialId, info =
 * "qntx-wallet/kek/passkey/v1", 32). Wipes `prf` in every case.
 */
export function passkeyKek(prf: Uint8Array, credentialId: Uint8Array): Uint8Array {
  try {
    if (prf.length !== 32) {
      throw new KernelError("invalid-input", "PRF output must be 32 bytes");
    }
    return hkdf(sha256, prf, credentialId, utf8ToBytes("qntx-wallet/kek/passkey/v1"), 32);
  } finally {
    wipe(prf);
  }
}

/** The factor's public wrapping key: X25519(HKDF-SHA256(KEK)). Public — safe to store in headers. */
export function factorPublicKey(kek: Uint8Array): Uint8Array {
  const factorSk = hkdf(sha256, kek, new Uint8Array(0), FACTOR_KEY_INFO, 32);
  try {
    return x25519.getPublicKey(factorSk);
  } finally {
    wipe(factorSk);
  }
}

/** The `publicKey` a factor header declares, decoded; malformed headers throw `integrity`. */
export function factorHeaderPublicKey(stored: StoredFactor): Uint8Array {
  const header =
    stored.kind === "password"
      ? parsePasswordFactorHeader(stored.header)
      : parsePasskeyFactorHeader(stored.header);
  return base64urlnopad.decode(header.publicKey);
}

/** The binding tag a `sealed` factor row must carry for `dek` (constant-time verified). */
function factorBinding(dekBytes: Uint8Array, context: string, header: string): Uint8Array {
  return hmac(sha256, dekBytes, concatBytes(BINDING_TAG, aadOf(context, header)));
}

/**
 * Whether the stored factor row binds `dek` — structure check plus the HMAC tag. No KEK is needed:
 * the tag proves the row was written for this DEK by someone who held it.
 */
export function factorBindingOk(dek: Secret, stored: StoredFactor): boolean {
  const { sealed } = stored;
  if (sealed.length !== WRAPPED_DEK_LENGTH || sealed[0] !== WRAP_VERSION) {
    return false;
  }
  const expected = dek.use((bytes) =>
    factorBinding(bytes, factorContext(stored.kind, stored.id), stored.header),
  );
  try {
    return equalBytes(expected, sealed.subarray(33, 65));
  } finally {
    wipe(expected);
  }
}

export type FactorRef = {
  readonly kind: StoredFactor["kind"];
  readonly id: string;
  readonly header: string; // raw JSON text, authenticated verbatim
};

/**
 * Seals the DEK to a factor's public key — no KEK needed, so rotation can re-wrap to factors it
 * cannot unlock. `factorPk` is the 32-byte X25519 public key from the factor's header.
 */
export function wrapDek(
  dek: Secret,
  factorPk: Uint8Array,
  factor: FactorRef,
  random: Random,
): Uint8Array {
  const eph = random(32);
  try {
    const ephPk = x25519.getPublicKey(eph);
    const shared = x25519.getSharedSecret(eph, factorPk);
    try {
      if (equalBytes(shared, ZERO32)) {
        throw new KernelError("integrity", "weak factor public key");
      }
      const wrapKey = hkdf(sha256, shared, concatBytes(ephPk, factorPk), WRAP_INFO, 32);
      try {
        const envelope = dek.use((bytes) =>
          seal(wrapKey, bytes, factorContext(factor.kind, factor.id), factor.header, random),
        );
        const binding = dek.use((bytes) =>
          factorBinding(bytes, factorContext(factor.kind, factor.id), factor.header),
        );
        try {
          return concatBytes(new Uint8Array([WRAP_VERSION]), ephPk, binding, envelope);
        } finally {
          wipe(binding);
        }
      } finally {
        wipe(wrapKey);
      }
    } finally {
      wipe(shared);
    }
  } finally {
    wipe(eph);
  }
}

const corruptError = (message: string): KernelError =>
  new KernelError("integrity", message, undefined, true);

/**
 * Opens a stored factor's wrapped DEK. A KEK that does not belong to this factor fails the cheap
 * public-key check before any AEAD runs — `wrong-password` for password factors (the counter
 * decides what it means), `wrong-passkey` for passkeys. A row whose structure, ciphertext or
 * binding is broken reports `integrity` marked corrupted.
 */
export function unwrapDek(kek: Uint8Array, stored: StoredFactor): Secret {
  const factorSk = hkdf(sha256, kek, new Uint8Array(0), FACTOR_KEY_INFO, 32);
  try {
    const factorPk = x25519.getPublicKey(factorSk);
    if (!equalBytes(factorPk, factorHeaderPublicKey(stored))) {
      throw stored.kind === "password"
        ? new KernelError("wrong-password", "password did not open the vault")
        : new KernelError("wrong-passkey", "passkey does not match the factor");
    }
    const { sealed } = stored;
    if (sealed.length !== WRAPPED_DEK_LENGTH || sealed[0] !== WRAP_VERSION) {
      throw corruptError("malformed factor wrapping");
    }
    const ephPk = sealed.subarray(1, 33);
    const binding = sealed.subarray(33, 65);
    let shared: Uint8Array;
    try {
      shared = x25519.getSharedSecret(factorSk, ephPk);
    } catch {
      throw corruptError("invalid factor ephemeral key");
    }
    try {
      if (equalBytes(shared, ZERO32)) {
        throw corruptError("weak factor ephemeral key");
      }
      const wrapKey = hkdf(sha256, shared, concatBytes(ephPk, factorPk), WRAP_INFO, 32);
      try {
        let dekBytes: Uint8Array;
        try {
          dekBytes = open(
            wrapKey,
            sealed.subarray(65),
            factorContext(stored.kind, stored.id),
            stored.header,
          );
        } catch {
          throw corruptError("factor wrapping failed authentication");
        }
        const expected = factorBinding(
          dekBytes,
          factorContext(stored.kind, stored.id),
          stored.header,
        );
        const bound = equalBytes(expected, binding);
        wipe(expected);
        if (!bound) {
          wipe(dekBytes);
          throw corruptError("factor binding mismatch");
        }
        return Secret.take(dekBytes);
      } finally {
        wipe(wrapKey);
      }
    } finally {
      wipe(shared);
    }
  } finally {
    wipe(factorSk);
  }
}
