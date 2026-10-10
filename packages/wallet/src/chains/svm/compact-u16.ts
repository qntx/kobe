import { SignError } from "../../errors/sign.ts";

/** Decode Solana compact-u16. Returns [value, headerLen]. */
export function decodeCompactU16(data: Uint8Array): { value: number; headerLen: number } {
  let value = 0;
  let shift = 0;
  for (let i = 0; i < data.length; i++) {
    if (i >= 3) {
      throw new SignError("invalid_transaction", "compact-u16 exceeds 3 bytes");
    }
    const byte = data[i]!;
    value |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) return { value, headerLen: i + 1 };
    shift += 7;
  }
  throw new SignError("invalid_transaction", "truncated compact-u16");
}

export function extractSignableBytes(txBytes: Uint8Array): Uint8Array {
  if (txBytes.length === 0) {
    throw new SignError("invalid_transaction", "empty transaction");
  }
  const { value: numSigs, headerLen } = decodeCompactU16(txBytes);
  const msgStart = headerLen + numSigs * 64;
  if (txBytes.length <= msgStart) {
    throw new SignError("invalid_transaction", "transaction too short");
  }
  return txBytes.subarray(msgStart);
}

export function spliceSignature(txBytes: Uint8Array, signature: Uint8Array): Uint8Array {
  if (txBytes.length === 0) {
    throw new SignError("invalid_transaction", "empty transaction");
  }
  if (signature.length !== 64) {
    throw new SignError("invalid_signature", "ed25519 signature must be 64 bytes");
  }
  const { value: numSigs, headerLen } = decodeCompactU16(txBytes);
  if (numSigs === 0) {
    throw new SignError("invalid_transaction", "no signature slots");
  }
  if (txBytes.length < headerLen + numSigs * 64) {
    throw new SignError("invalid_transaction", "transaction too short");
  }
  const signed = new Uint8Array(txBytes);
  signed.set(signature, headerLen);
  return signed;
}
