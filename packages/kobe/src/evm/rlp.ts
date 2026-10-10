import { KobeError } from "../core/error.ts";
import type { RecoverableSignature } from "../core/signature.ts";

/** RLP-encode a byte string. */
export function encodeBytes(data: Uint8Array): Uint8Array {
  const only = data.at(0);
  if (data.length === 1 && only !== undefined && only < 0x80) {
    return new Uint8Array(data);
  }
  const prefix = encodeLength(data.length, 0x80);
  const out = new Uint8Array(prefix.length + data.length);
  out.set(prefix, 0);
  out.set(data, prefix.length);
  return out;
}

/** RLP-encode an integer as a minimal-width byte string (`0n` → `0x80`). */
export function encodeUint(value: bigint): Uint8Array {
  return encodeBytes(stripLeadingZeros(bigEndian(value)));
}

/** RLP-encode a list from already-encoded concatenated items. */
export function encodeList(items: Uint8Array): Uint8Array {
  const prefix = encodeLength(items.length, 0xc0);
  const out = new Uint8Array(prefix.length + items.length);
  out.set(prefix, 0);
  out.set(items, prefix.length);
  return out;
}

/** Strip leading zeros from a big-endian scalar. */
export function stripLeadingZeros(data: Uint8Array): Uint8Array {
  let start = 0;
  while (start < data.length && data[start] === 0) {
    start++;
  }
  return data.subarray(start);
}

/**
 * Decode `data` as a single RLP list spanning it exactly and return its payload (the concatenation
 * of the encoded items).
 *
 * @throws KobeError input on a non-list item or trailing bytes
 */
export function decodeList(data: Uint8Array): Uint8Array {
  const prefix = data.at(0);
  if (prefix === undefined || prefix < 0xc0) {
    throw new KobeError("input", "expected an RLP list");
  }
  const { offset, length } = decodeLength(data);
  if (data.length < offset + length) {
    throw new KobeError("input", "truncated RLP payload");
  }
  if (data.length !== offset + length) {
    throw new KobeError("input", "trailing bytes after RLP list");
  }
  return data.subarray(offset, offset + length);
}

/** Split an RLP list payload into its encoded items. */
export function listItems(payload: Uint8Array): Uint8Array[] {
  const items: Uint8Array[] = [];
  let rest = payload;
  while (rest.length > 0) {
    const { offset, length } = decodeLength(rest);
    if (rest.length < offset + length) {
      throw new KobeError("input", "truncated RLP item");
    }
    items.push(rest.subarray(0, offset + length));
    rest = rest.subarray(offset + length);
  }
  return items;
}

/**
 * Decode one item and return its payload bytes (without the length prefix). The item must be a byte
 * string, not a nested list.
 */
export function itemPayload(item: Uint8Array): Uint8Array {
  const prefix = item.at(0);
  if (prefix === undefined || prefix >= 0xc0) {
    throw new KobeError("input", "expected an RLP byte string, got a list");
  }
  const { offset, length } = decodeLength(item);
  if (item.length !== offset + length) {
    throw new KobeError("input", "malformed RLP item");
  }
  return item.subarray(offset, offset + length);
}

/** `true` when the encoded item is the RLP empty string (`0x80`). */
export function isRlpZero(item: Uint8Array): boolean {
  return item.length === 1 && item.at(0) === 0x80;
}

/**
 * Append `(yParity, r, s)` to an unsigned typed transaction.
 *
 * Input: `type_byte ‖ RLP([…fields])` with `type_byte` `0x01`, `0x02` or `0x04`. Output: `type_byte
 * ‖ RLP([…fields, yParity, r, s])` — `yParity` is the raw recovery bit (`0` encodes as `0x80`);
 * `r`/`s` have leading zeros stripped.
 *
 * @throws KobeError input on an empty input, unsupported type byte or malformed list
 */
export function encodeSignedTypedTransaction(
  unsigned: Uint8Array,
  signature: RecoverableSignature,
): Uint8Array {
  if (unsigned.length === 0) {
    throw new KobeError("input", "empty transaction");
  }
  const [typeByte] = unsigned;
  if (typeByte !== 0x01 && typeByte !== 0x02 && typeByte !== 0x04) {
    throw new KobeError("input", "unsupported transaction type (expected 0x01, 0x02 or 0x04)");
  }
  const items = decodeList(unsigned.subarray(1));
  const r = signature.signature.subarray(0, 32);
  const s = signature.signature.subarray(32, 64);
  const yParity = signature.recovery;
  const tail = concatEncoded([
    encodeBytes(stripLeadingZeros(Uint8Array.of(yParity))),
    encodeBytes(stripLeadingZeros(r)),
    encodeBytes(stripLeadingZeros(s)),
  ]);
  const newItems = concatEncoded([items, tail]);
  const list = encodeList(newItems);
  const out = new Uint8Array(1 + list.length);
  out[0] = typeByte;
  out.set(list, 1);
  return out;
}

/**
 * Rebuild a signed legacy transaction from a validated 9-item unsigned envelope.
 *
 * Output: `RLP([nonce, gasPrice, gasLimit, to, value, data, v, r, s])` with `v = chainId * 2 + 35 +
 * recovery` (EIP-155).
 */
export function encodeSignedLegacyTransaction(
  unsigned: Uint8Array,
  signature: RecoverableSignature,
  chainId: bigint,
): Uint8Array {
  const payload = decodeList(unsigned);
  const items = listItems(payload);
  const v = chainId * 2n + 35n + BigInt(signature.recovery);
  const r = signature.signature.subarray(0, 32);
  const s = signature.signature.subarray(32, 64);
  const first = items.slice(0, 6);
  const newItems = concatEncoded([
    ...first,
    encodeUint(v),
    encodeBytes(stripLeadingZeros(r)),
    encodeBytes(stripLeadingZeros(s)),
  ]);
  return encodeList(newItems);
}

/** Concatenate already-encoded RLP items. */
export function concatEncoded(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/** Minimal-width big-endian bytes of a non-negative bigint. */
export function bigEndian(value: bigint): Uint8Array {
  if (value < 0n) {
    throw new KobeError("input", "RLP integers are unsigned");
  }
  let hex = value.toString(16);
  if (hex.length % 2 !== 0) {
    hex = `0${hex}`;
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function encodeLength(len: number, offset: number): Uint8Array {
  if (len < 56) {
    return Uint8Array.of(offset + len);
  }
  const lenBytes = stripLeadingZeros(bigEndian(BigInt(len)));
  const out = new Uint8Array(1 + lenBytes.length);
  out[0] = offset + 55 + lenBytes.length;
  out.set(lenBytes, 1);
  return out;
}

function decodeLength(data: Uint8Array): { offset: number; length: number } {
  const prefix = data.at(0);
  if (prefix === undefined) {
    throw new KobeError("input", "empty input");
  }
  if (prefix <= 0x7f) {
    return { offset: 0, length: 1 };
  }
  if (prefix <= 0xb7) {
    return { offset: 1, length: prefix - 0x80 };
  }
  if (prefix <= 0xbf) {
    const n = prefix - 0xb7;
    if (data.length < 1 + n) {
      throw new KobeError("input", "truncated length");
    }
    return { offset: 1 + n, length: readBe(data.subarray(1, 1 + n)) };
  }
  if (prefix <= 0xf7) {
    return { offset: 1, length: prefix - 0xc0 };
  }
  const n = prefix - 0xf7;
  if (data.length < 1 + n) {
    throw new KobeError("input", "truncated length");
  }
  return { offset: 1 + n, length: readBe(data.subarray(1, 1 + n)) };
}

function readBe(bytes: Uint8Array): number {
  let acc = 0;
  for (const b of bytes) {
    acc = acc * 256 + b;
  }
  return acc;
}
