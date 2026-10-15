/**
 * PBKDF2 through `crypto.subtle` — shared by the Node worker and (in W4) the browser worker.
 * WebCrypto exists identically in both; nothing here touches Node or DOM APIs.
 */
import type { Pbkdf2 } from "@qntx/wallet-kernel";

const SUBTLE_HASH: Readonly<Record<"sha256" | "sha512", string>> = {
  sha256: "SHA-256",
  sha512: "SHA-512",
};

export const subtlePbkdf2: Pbkdf2 = async (hash, password, salt, iterations, length) => {
  // Copy into fresh ArrayBuffer-backed views: BufferSource wants Uint8Array<ArrayBuffer>,
  // and the password copy is ours to wipe after importKey has consumed it.
  const passwordCopy = new Uint8Array(password);
  const saltCopy = new Uint8Array(salt);
  try {
    const key = await crypto.subtle.importKey("raw", passwordCopy, "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: SUBTLE_HASH[hash] ?? "SHA-256", salt: saltCopy, iterations },
      key,
      length * 8,
    );
    return new Uint8Array(bits);
  } finally {
    passwordCopy.fill(0);
  }
};
