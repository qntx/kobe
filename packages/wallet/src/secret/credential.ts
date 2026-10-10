import { gcm } from "@noble/ciphers/aes.js";
import { pbkdf2Sha256 } from "../crypto/index.ts";
import { bytesToHex, hexToBytes } from "../crypto/hex.ts";
import { DeriveError } from "../errors/derive.ts";
import { wipeBytes } from "./dispose.ts";

const MAGIC = new TextEncoder().encode("WSEC");
const VERSION = 2;
const KDF_PBKDF2_SHA256 = 1;
const DEFAULT_ITERATIONS = 600_000;
const SALT_LEN = 32;
const NONCE_LEN = 12;
const KEY_LEN = 32;

export interface CredentialBlob {
  readonly version: 2;
  readonly kdf: "pbkdf2-sha256";
  readonly iterations: number;
  readonly salt: Uint8Array;
  readonly nonce: Uint8Array;
  /** Ciphertext including the 16-byte GCM tag. */
  readonly ciphertext: Uint8Array;
}

export interface EncryptCredentialOptions {
  iterations?: number;
  rng?: (bytes: Uint8Array) => void;
}

function fillRandom(bytes: Uint8Array, rng?: (bytes: Uint8Array) => void): void {
  if (rng) {
    rng(bytes);
    return;
  }
  if (typeof globalThis.crypto?.getRandomValues !== "function") {
    throw new DeriveError("crypto", "no CSPRNG: pass encrypt options.rng");
  }
  const buf = new Uint8Array(bytes.length);
  globalThis.crypto.getRandomValues(buf);
  bytes.set(buf);
}

function deriveKey(password: string, salt: Uint8Array, iterations: number): Uint8Array {
  if (password.length === 0) {
    throw new DeriveError("input", "password must not be empty");
  }
  if (!Number.isInteger(iterations) || iterations < 1) {
    throw new DeriveError("input", "iterations must be a positive integer");
  }
  return pbkdf2Sha256(new TextEncoder().encode(password), salt, iterations, KEY_LEN);
}

/** Envelope header through nonce. Bound as GCM AAD. */
function envelopeHeader(iterations: number, salt: Uint8Array, nonce: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + 1 + 1 + 4 + 1 + salt.length + 1 + nonce.length);
  let o = 0;
  out.set(MAGIC, o);
  o += 4;
  out[o++] = VERSION;
  out[o++] = KDF_PBKDF2_SHA256;
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  view.setUint32(o, iterations, false);
  o += 4;
  out[o++] = salt.length;
  out.set(salt, o);
  o += salt.length;
  out[o++] = nonce.length;
  out.set(nonce, o);
  return out;
}

/**
 * Encrypt arbitrary bytes with AES-256-GCM.
 * Key = PBKDF2-HMAC-SHA256(password, salt, iterations, 32).
 * AAD = magic || ver || kdf || iter_be || saltLen || salt || nonceLen || nonce.
 */
export function encryptBytes(
  plaintext: Uint8Array,
  password: string,
  opts: EncryptCredentialOptions = {},
): CredentialBlob {
  const iterations = opts.iterations ?? DEFAULT_ITERATIONS;
  const salt = new Uint8Array(SALT_LEN);
  const nonce = new Uint8Array(NONCE_LEN);
  fillRandom(salt, opts.rng);
  fillRandom(nonce, opts.rng);
  const key = deriveKey(password, salt, iterations);
  const aad = envelopeHeader(iterations, salt, nonce);
  try {
    const ciphertext = gcm(key, nonce, aad).encrypt(plaintext);
    return {
      version: VERSION,
      kdf: "pbkdf2-sha256",
      iterations,
      salt,
      nonce,
      ciphertext,
    };
  } finally {
    wipeBytes(key);
  }
}

/** Decrypt a blob. Wrong password / tamper / v1 → DeriveError input. */
export function decryptBytes(blob: CredentialBlob, password: string): Uint8Array {
  if (blob.version !== VERSION) {
    throw new DeriveError("input", `unsupported credential version ${String(blob.version)}`);
  }
  if (blob.kdf !== "pbkdf2-sha256") {
    throw new DeriveError("input", `unsupported credential kdf '${String(blob.kdf)}'`);
  }
  if (blob.salt.length !== SALT_LEN || blob.nonce.length !== NONCE_LEN) {
    throw new DeriveError("input", "credential salt/nonce length");
  }
  const key = deriveKey(password, blob.salt, blob.iterations);
  const aad = envelopeHeader(blob.iterations, blob.salt, blob.nonce);
  try {
    return gcm(key, blob.nonce, aad).decrypt(blob.ciphertext);
  } catch (e) {
    throw new DeriveError("input", "incorrect password or tampered credential", { cause: e });
  } finally {
    wipeBytes(key);
  }
}

export function encryptMnemonic(
  phrase: string,
  password: string,
  opts: EncryptCredentialOptions = {},
): CredentialBlob {
  return encryptBytes(new TextEncoder().encode(phrase), password, opts);
}

export function decryptMnemonic(blob: CredentialBlob, password: string): string {
  return new TextDecoder().decode(decryptBytes(blob, password));
}

export function encryptSecret32(
  secret: Uint8Array,
  password: string,
  opts: EncryptCredentialOptions = {},
): CredentialBlob {
  if (secret.length !== 32) {
    throw new DeriveError("crypto", `secret must be 32 bytes, got ${secret.length}`);
  }
  return encryptBytes(secret, password, opts);
}

export function decryptSecret32(blob: CredentialBlob, password: string): Uint8Array {
  const out = decryptBytes(blob, password);
  if (out.length !== 32) {
    wipeBytes(out);
    throw new DeriveError("crypto", `decrypted secret must be 32 bytes, got ${out.length}`);
  }
  return out;
}

/** Binary envelope: `WSEC` || ver || kdf || iter_be || saltLen || salt || nonceLen || nonce || ct. */
export function credentialToBytes(blob: CredentialBlob): Uint8Array {
  const header = envelopeHeader(blob.iterations, blob.salt, blob.nonce);
  const out = new Uint8Array(header.length + blob.ciphertext.length);
  out.set(header);
  out.set(blob.ciphertext, header.length);
  return out;
}

export function credentialFromBytes(bytes: Uint8Array): CredentialBlob {
  if (bytes.length < 4 + 1) {
    throw new DeriveError("input", "credential envelope too short");
  }
  for (let i = 0; i < 4; i++) {
    if (bytes[i] !== MAGIC[i]) throw new DeriveError("input", "credential magic mismatch");
  }
  let o = 4;
  const version = bytes[o++]!;
  if (version !== VERSION) {
    throw new DeriveError("input", `unsupported credential version ${version}`);
  }
  if (bytes.length < 4 + 1 + 1 + 4 + 1 + SALT_LEN + 1 + NONCE_LEN + 16) {
    throw new DeriveError("input", "credential envelope too short");
  }
  const kdf = bytes[o++]!;
  if (kdf !== KDF_PBKDF2_SHA256) {
    throw new DeriveError("input", `unsupported credential kdf ${kdf}`);
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const iterations = view.getUint32(o, false);
  o += 4;
  const saltLen = bytes[o++]!;
  if (saltLen !== SALT_LEN || o + saltLen > bytes.length) {
    throw new DeriveError("input", "credential salt length");
  }
  const salt = bytes.slice(o, o + saltLen);
  o += saltLen;
  const nonceLen = bytes[o++]!;
  if (nonceLen !== NONCE_LEN || o + nonceLen > bytes.length) {
    throw new DeriveError("input", "credential nonce length");
  }
  const nonce = bytes.slice(o, o + nonceLen);
  o += nonceLen;
  const ciphertext = bytes.slice(o);
  if (ciphertext.length < 16) {
    throw new DeriveError("input", "credential ciphertext too short");
  }
  return { version: VERSION, kdf: "pbkdf2-sha256", iterations, salt, nonce, ciphertext };
}

export function credentialToHex(blob: CredentialBlob): string {
  return bytesToHex(credentialToBytes(blob));
}

export function credentialFromHex(hex: string): CredentialBlob {
  try {
    return credentialFromBytes(hexToBytes(hex));
  } catch (e) {
    if (e instanceof DeriveError) throw e;
    throw new DeriveError("input", e instanceof Error ? e.message : "invalid credential hex", {
      cause: e,
    });
  }
}
