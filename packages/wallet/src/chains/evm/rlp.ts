import { SignError } from "../../errors/sign.ts";

export function encodeBytes(data: Uint8Array): Uint8Array {
  if (data.length === 1 && data[0]! < 0x80) return new Uint8Array(data);
  const prefix = encodeLength(data.length, 0x80);
  const out = new Uint8Array(prefix.length + data.length);
  out.set(prefix, 0);
  out.set(data, prefix.length);
  return out;
}

export function encodeList(items: Uint8Array): Uint8Array {
  const prefix = encodeLength(items.length, 0xc0);
  const out = new Uint8Array(prefix.length + items.length);
  out.set(prefix, 0);
  out.set(items, prefix.length);
  return out;
}

export function stripLeadingZeros(data: Uint8Array): Uint8Array {
  let start = 0;
  while (start < data.length && data[start] === 0) start++;
  return data.subarray(start);
}

function encodeLength(len: number, offset: number): Uint8Array {
  if (len < 56) return Uint8Array.of(offset + len);
  const lenBytes = beBytes(len);
  const out = new Uint8Array(1 + lenBytes.length);
  out[0] = offset + 55 + lenBytes.length;
  out.set(lenBytes, 1);
  return out;
}

function beBytes(val: number): Uint8Array {
  if (val === 0) return Uint8Array.of(0);
  const bytes: number[] = [];
  let n = val;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n = Math.floor(n / 256);
  }
  return Uint8Array.from(bytes);
}

function decodeLength(data: Uint8Array): { offset: number; length: number } {
  if (data.length === 0) throw new SignError("invalid_transaction", "empty input");
  const prefix = data[0]!;
  if (prefix <= 0x7f) return { offset: 0, length: 1 };
  if (prefix <= 0xb7) return { offset: 1, length: prefix - 0x80 };
  if (prefix <= 0xbf) {
    const n = prefix - 0xb7;
    if (data.length < 1 + n) throw new SignError("invalid_transaction", "truncated length");
    return { offset: 1 + n, length: readBe(data.subarray(1, 1 + n)) };
  }
  if (prefix <= 0xf7) return { offset: 1, length: prefix - 0xc0 };
  const n = prefix - 0xf7;
  if (data.length < 1 + n) throw new SignError("invalid_transaction", "truncated length");
  return { offset: 1 + n, length: readBe(data.subarray(1, 1 + n)) };
}

function readBe(bytes: Uint8Array): number {
  let acc = 0;
  for (const b of bytes) acc = (acc << 8) | b;
  return acc;
}

/** `type || RLP([…fields, v, r, s])` for typed tx 0x01 / 0x02. */
export function encodeSignedTypedTx(
  unsignedTx: Uint8Array,
  v: number,
  r: Uint8Array,
  s: Uint8Array,
): Uint8Array {
  if (unsignedTx.length === 0) {
    throw new SignError("invalid_transaction", "empty transaction");
  }
  const typeByte = unsignedTx[0]!;
  if (typeByte !== 0x01 && typeByte !== 0x02) {
    throw new SignError(
      "invalid_transaction",
      "unsupported transaction type (expected 0x01 or 0x02)",
    );
  }
  const rlpData = unsignedTx.subarray(1);
  const { offset, length } = decodeLength(rlpData);
  if (rlpData.length < offset + length) {
    throw new SignError("invalid_transaction", "truncated RLP payload");
  }
  const items = rlpData.subarray(offset, offset + length);
  const vEnc = encodeBytes(stripLeadingZeros(Uint8Array.of(v & 0xff)));
  const rEnc = encodeBytes(stripLeadingZeros(r));
  const sEnc = encodeBytes(stripLeadingZeros(s));
  const newItems = new Uint8Array(items.length + vEnc.length + rEnc.length + sEnc.length);
  newItems.set(items, 0);
  newItems.set(vEnc, items.length);
  newItems.set(rEnc, items.length + vEnc.length);
  newItems.set(sEnc, items.length + vEnc.length + rEnc.length);
  const list = encodeList(newItems);
  const result = new Uint8Array(1 + list.length);
  result[0] = typeByte;
  result.set(list, 1);
  return result;
}

/** Concatenate already-encoded RLP items (for tests / unsigned envelopes). */
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
