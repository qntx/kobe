import { SignError } from "../../errors/sign.ts";

const TX_TYPE_EIP2930 = 0x01;
const TX_TYPE_EIP1559 = 0x02;
const TX_TYPE_EIP7702 = 0x04;
const U64_MAX = 2n ** 64n - 1n;

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

/** RLP-encode an unsigned integer as a minimal-width byte string (`0n` → `0x80`). */
function encodeUint(value: bigint): Uint8Array {
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

/**
 * Decode `data` as a single RLP list spanning it exactly and return its payload (the concatenation
 * of the encoded items).
 *
 * @throws SignError invalid_transaction on a non-list item or trailing bytes
 */
function decodeList(data: Uint8Array): Uint8Array {
  const prefix = data.at(0);
  if (prefix === undefined || prefix < 0xc0) {
    throw new SignError("invalid_transaction", "expected an RLP list");
  }
  const { offset, length } = decodeLength(data);
  if (data.length < offset + length) {
    throw new SignError("invalid_transaction", "truncated RLP payload");
  }
  if (data.length !== offset + length) {
    throw new SignError("invalid_transaction", "trailing bytes after RLP list");
  }
  return data.subarray(offset, offset + length);
}

/** Split an RLP list payload into its encoded items. */
function listItems(payload: Uint8Array): Uint8Array[] {
  const items: Uint8Array[] = [];
  let rest = payload;
  while (rest.length > 0) {
    const { offset, length } = decodeLength(rest);
    if (rest.length < offset + length) {
      throw new SignError("invalid_transaction", "truncated RLP item");
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
function itemPayload(item: Uint8Array): Uint8Array {
  const prefix = item.at(0);
  if (prefix === undefined || prefix >= 0xc0) {
    throw new SignError("invalid_transaction", "expected an RLP byte string, got a list");
  }
  const { offset, length } = decodeLength(item);
  if (item.length !== offset + length) {
    throw new SignError("invalid_transaction", "malformed RLP item");
  }
  return item.subarray(offset, offset + length);
}

/** `true` when the encoded item is the RLP empty string (`0x80`). */
function isRlpZero(item: Uint8Array): boolean {
  return item.length === 1 && item.at(0) === 0x80;
}

/** Shape of a validated unsigned transaction envelope. */
export type UnsignedEnvelope =
  | { readonly kind: "typed"; readonly typeByte: number }
  | { readonly kind: "legacy"; readonly chainId: bigint };

/**
 * Validate an unsigned transaction envelope and report its shape.
 *
 * - Typed: first byte `0x01` (EIP-2930), `0x02` (EIP-1559) or `0x04` (EIP-7702) followed by one
 *   well-formed RLP list spanning the rest of the bytes exactly. `0x03` (EIP-4844) and any other
 *   type byte are rejected.
 * - Legacy: a bare RLP list with exactly 9 items — the EIP-155 unsigned form `[nonce, gasPrice,
 *   gasLimit, to, value, data, chainId, 0, 0]` — whose last two items are empty and whose `chainId`
 *   fits in 8 bytes. A 6-item pre-EIP-155 list is rejected.
 *
 * @throws SignError invalid_transaction on a malformed or unsupported envelope
 */
export function validateUnsignedEnvelope(unsignedTx: Uint8Array): UnsignedEnvelope {
  const first = unsignedTx.at(0);
  if (first === undefined) {
    throw new SignError("invalid_transaction", "empty transaction");
  }
  if (first === TX_TYPE_EIP2930 || first === TX_TYPE_EIP1559 || first === TX_TYPE_EIP7702) {
    decodeList(unsignedTx.subarray(1));
    return { kind: "typed", typeByte: first };
  }
  if (first >= 0xc0) {
    const chainId = validateLegacyItems(listItems(decodeList(unsignedTx)));
    return { kind: "legacy", chainId };
  }
  throw new SignError("invalid_transaction", "unsupported transaction type");
}

/**
 * `type ‖ RLP([…fields, yParity, r, s])` for typed tx `0x01` / `0x02` / `0x04`. `yParity` is the
 * raw recovery bit (`0` encodes as `0x80`); `r`/`s` have leading zeros stripped.
 *
 * @throws SignError invalid_transaction on an empty input, unsupported type byte or malformed list
 */
export function encodeSignedTypedTx(
  unsignedTx: Uint8Array,
  yParity: number,
  r: Uint8Array,
  s: Uint8Array,
): Uint8Array {
  const envelope = validateUnsignedEnvelope(unsignedTx);
  if (envelope.kind !== "typed") {
    throw new SignError(
      "invalid_transaction",
      "unsupported transaction type (expected 0x01, 0x02 or 0x04)",
    );
  }
  const rlpData = unsignedTx.subarray(1);
  const { offset, length } = decodeLength(rlpData);
  const items = rlpData.subarray(offset, offset + length);
  const tail = concatEncoded([
    encodeBytes(stripLeadingZeros(Uint8Array.of(yParity))),
    encodeBytes(stripLeadingZeros(r)),
    encodeBytes(stripLeadingZeros(s)),
  ]);
  const newItems = concatEncoded([items, tail]);
  const list = encodeList(newItems);
  const result = new Uint8Array(1 + list.length);
  result[0] = envelope.typeByte;
  result.set(list, 1);
  return result;
}

/**
 * Rebuild a signed legacy transaction from a validated 9-item unsigned envelope: `RLP([nonce,
 * gasPrice, gasLimit, to, value, data, v, r, s])` with `v = chainId * 2 + 35 + yParity` (EIP-155).
 * `r`/`s` have leading zeros stripped.
 *
 * @throws SignError invalid_transaction on a malformed envelope or a 6-item legacy list
 */
export function encodeSignedLegacyTx(
  unsignedTx: Uint8Array,
  chainId: bigint,
  yParity: number,
  r: Uint8Array,
  s: Uint8Array,
): Uint8Array {
  const items = listItems(decodeList(unsignedTx));
  // chain_id ≤ u64, so v fits comfortably in f64-safe bigint arithmetic.
  const v = chainId * 2n + 35n + BigInt(yParity);
  const first = items.slice(0, 6);
  const newItems = concatEncoded([
    ...first,
    encodeUint(v),
    encodeBytes(stripLeadingZeros(r)),
    encodeBytes(stripLeadingZeros(s)),
  ]);
  return encodeList(newItems);
}

/** Validate the 9-item EIP-155 unsigned form and return its chain id. */
function validateLegacyItems(items: Uint8Array[]): bigint {
  if (items.length === 6) {
    throw new SignError("invalid_transaction", "legacy transaction must carry an EIP-155 chain id");
  }
  if (items.length !== 9) {
    throw new SignError("invalid_transaction", "legacy transaction must contain 9 fields");
  }
  const chainItem = items.at(6);
  const padR = items.at(7);
  const padS = items.at(8);
  if (chainItem === undefined || padR === undefined || padS === undefined) {
    throw new SignError("invalid_transaction", "legacy transaction must contain 9 fields");
  }
  if (!isRlpZero(padR) || !isRlpZero(padS)) {
    throw new SignError("invalid_transaction", "legacy EIP-155 placeholder fields must be empty");
  }
  const chainId = itemPayload(chainItem);
  if (chainId.length > 8) {
    throw new SignError("invalid_transaction", "legacy chain id exceeds u64");
  }
  let id = 0n;
  for (const b of chainId) {
    id = id * 256n + BigInt(b);
  }
  return id;
}

/** Encode `0x05 ‖ RLP([chainId, address, nonce])` — the EIP-7702 authorization preimage. */
export function encodeAuthorization(
  chainId: bigint,
  address: Uint8Array,
  nonce: bigint,
): Uint8Array {
  if (chainId < 0n || chainId > U64_MAX) {
    throw new SignError("invalid_message", "chainId must fit in u64");
  }
  if (nonce < 0n || nonce > U64_MAX) {
    throw new SignError("invalid_message", "nonce must fit in u64");
  }
  if (address.length !== 20) {
    throw new SignError("invalid_message", `address must be 20 bytes, got ${address.length}`);
  }
  const items = concatEncoded([encodeUint(chainId), encodeBytes(address), encodeUint(nonce)]);
  const list = encodeList(items);
  const out = new Uint8Array(1 + list.length);
  out[0] = 0x05;
  out.set(list, 1);
  return out;
}

function encodeLength(len: number, offset: number): Uint8Array {
  if (len < 56) {
    return Uint8Array.of(offset + len);
  }
  const lenBytes = stripLeadingZeros(beBytes(len));
  const out = new Uint8Array(1 + lenBytes.length);
  out[0] = offset + 55 + lenBytes.length;
  out.set(lenBytes, 1);
  return out;
}

/** Minimal-width big-endian bytes of a non-negative bigint. */
function bigEndian(value: bigint): Uint8Array {
  if (value < 0n) {
    throw new SignError("invalid_transaction", "RLP integers are unsigned");
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

function beBytes(val: number): Uint8Array {
  if (val === 0) {
    return Uint8Array.of(0);
  }
  const bytes: number[] = [];
  let n = val;
  while (n > 0) {
    bytes.unshift(n % 256);
    n = Math.floor(n / 256);
  }
  return Uint8Array.from(bytes);
}

function decodeLength(data: Uint8Array): { offset: number; length: number } {
  const prefix = data.at(0);
  if (prefix === undefined) {
    throw new SignError("invalid_transaction", "empty input");
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
      throw new SignError("invalid_transaction", "truncated length");
    }
    return { offset: 1 + n, length: readBe(data.subarray(1, 1 + n)) };
  }
  if (prefix <= 0xf7) {
    return { offset: 1, length: prefix - 0xc0 };
  }
  const n = prefix - 0xf7;
  if (data.length < 1 + n) {
    throw new SignError("invalid_transaction", "truncated length");
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
