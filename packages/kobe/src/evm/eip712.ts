import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

import { KobeError } from "../core/error.ts";

type TypeField = { name: string; type: string };
type TypeDefs = Map<string, TypeField[]>;

/**
 * EIP-712 v4 hash of a typed-data JSON document: `keccak256("\x19\x01" ‖ domainSeparator ‖
 * structHash)`.
 *
 * Supports nested structs, arrays, `bytes`/`bytesN`, `string`, `bool`, `address` and `intN`/`uintN`
 * (full 256-bit range, decimal or hex literals).
 *
 * @throws KobeError input on malformed JSON or invalid typed data
 */
export function hashTypedDataJson(json: string): Uint8Array {
  let v: unknown;
  try {
    v = JSON.parse(json) as unknown;
  } catch (error) {
    throw new KobeError("input", error instanceof Error ? error.message : "invalid JSON", {
      cause: error,
    });
  }
  if (!isRecord(v)) {
    throw new KobeError("input", "typed data must be an object");
  }
  const rec = v;
  if (!isRecord(rec["types"])) {
    throw new KobeError("input", "missing 'types'");
  }
  if (typeof rec["primaryType"] !== "string") {
    throw new KobeError("input", "missing 'primaryType'");
  }
  if (!isRecord(rec["domain"])) {
    throw new KobeError("input", "missing 'domain'");
  }
  if (!isRecord(rec["message"])) {
    throw new KobeError("input", "missing 'message'");
  }
  const types = parseTypes(rec["types"]);
  const domainHash = hashStruct("EIP712Domain", rec["domain"], types);
  const messageHash = hashStruct(rec["primaryType"], rec["message"], types);
  const buf = new Uint8Array(2 + 32 + 32);
  buf[0] = 0x19;
  buf[1] = 0x01;
  buf.set(domainHash, 2);
  buf.set(messageHash, 34);
  return keccak_256(buf);
}

/** Narrow `unknown` to a plain object (non-null, non-array). */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Decode hex with an optional `0x`/`0X` prefix; failures map to KobeError input. */
function parseHex(value: string): Uint8Array {
  const h = value.startsWith("0x") || value.startsWith("0X") ? value.slice(2) : value;
  try {
    return hexToBytes(h);
  } catch (error) {
    throw new KobeError("input", error instanceof Error ? error.message : "invalid hex", {
      cause: error,
    });
  }
}

function parseTypes(val: unknown): TypeDefs {
  if (!isRecord(val)) {
    throw new KobeError("input", "'types' must be object");
  }
  const types: TypeDefs = new Map();
  for (const [name, fields] of Object.entries(val)) {
    if (!Array.isArray(fields)) {
      throw new KobeError("input", `${name}: expected array`);
    }
    const parsed: TypeField[] = [];
    for (const f of fields) {
      if (!isRecord(f)) {
        throw new KobeError("input", "field missing 'name'");
      }
      const fieldName = f["name"];
      const fieldType = f["type"];
      if (typeof fieldName !== "string" || typeof fieldType !== "string") {
        throw new KobeError("input", "field missing 'name' or 'type'");
      }
      parsed.push({ name: fieldName, type: fieldType });
    }
    types.set(name, parsed);
  }
  return types;
}

function hashStruct(typeName: string, data: unknown, types: TypeDefs): Uint8Array {
  const th = typeHash(typeName, types);
  const encoded = encodeData(typeName, data, types);
  const buf = new Uint8Array(32 + encoded.length);
  buf.set(th, 0);
  buf.set(encoded, 32);
  return keccak_256(buf);
}

function typeHash(typeName: string, types: TypeDefs): Uint8Array {
  return keccak_256(new TextEncoder().encode(encodeType(typeName, types)));
}

function encodeType(typeName: string, types: TypeDefs): string {
  const fields = types.get(typeName);
  if (!fields) {
    throw new KobeError("input", `unknown type: ${typeName}`);
  }
  const deps = new Set<string>();
  collectDeps(typeName, types, deps);
  deps.delete(typeName);
  let result = formatStruct(typeName, fields);
  for (const dep of [...deps].sort()) {
    const f = types.get(dep);
    if (f) {
      result += formatStruct(dep, f);
    }
  }
  return result;
}

function formatStruct(name: string, fields: TypeField[]): string {
  return `${name}(${fields.map((f) => `${f.type} ${f.name}`).join(",")})`;
}

function collectDeps(typeName: string, types: TypeDefs, out: Set<string>): void {
  const fields = types.get(typeName);
  if (!fields) {
    return;
  }
  for (const f of fields) {
    const base = baseType(f.type);
    if (types.has(base) && !out.has(base)) {
      out.add(base);
      collectDeps(base, types, out);
    }
  }
}

function baseType(t: string): string {
  const i = t.indexOf("[");
  return i === -1 ? t : t.slice(0, i);
}

function encodeData(typeName: string, data: unknown, types: TypeDefs): Uint8Array {
  const fields = types.get(typeName);
  if (!fields) {
    throw new KobeError("input", `unknown type: ${typeName}`);
  }
  if (!isRecord(data)) {
    throw new KobeError("input", `expected object for ${typeName}`);
  }
  const obj = data;
  const out = new Uint8Array(fields.length * 32);
  let o = 0;
  for (const f of fields) {
    out.set(encodeValue(f.type, obj[f.name] ?? null, types), o);
    o += 32;
  }
  return out;
}

function encodeValue(typeName: string, value: unknown, types: TypeDefs): Uint8Array {
  if (typeName.endsWith("]")) {
    const base = baseType(typeName);
    if (!Array.isArray(value)) {
      throw new KobeError("input", `expected array for ${typeName}`);
    }
    const inner = new Uint8Array(value.length * 32);
    let o = 0;
    for (const item of value) {
      inner.set(encodeValue(base, item, types), o);
      o += 32;
    }
    return keccak_256(inner);
  }
  if (types.has(typeName)) {
    return hashStruct(typeName, value, types);
  }
  return encodeAtomic(typeName, value);
}

function encodeAtomic(ty: string, value: unknown): Uint8Array {
  const w = new Uint8Array(32);
  if (ty === "address") {
    if (typeof value !== "string") {
      throw new KobeError("input", "address must be string");
    }
    const b = parseHex(value);
    if (b.length !== 20) {
      throw new KobeError("input", `address: expected 20 bytes, got ${b.length}`);
    }
    w.set(b, 12);
    return w;
  }
  if (ty === "bool") {
    w[31] = value === true ? 1 : 0;
    return w;
  }
  if (ty === "string") {
    if (typeof value !== "string") {
      throw new KobeError("input", "string must be string");
    }
    return keccak_256(new TextEncoder().encode(value));
  }
  if (ty === "bytes") {
    if (typeof value !== "string") {
      throw new KobeError("input", "bytes must be hex string");
    }
    return keccak_256(parseHex(value));
  }
  if (ty.startsWith("bytes") && ty.length > 5) {
    const n = Number(ty.slice(5));
    if (!Number.isInteger(n) || n < 1 || n > 32) {
      throw new KobeError("input", "bytesN: N must be 1..32");
    }
    if (typeof value !== "string") {
      throw new KobeError("input", `${ty} must be hex string`);
    }
    const b = parseHex(value);
    if (b.length !== n) {
      throw new KobeError("input", `${ty}: expected ${n} bytes, got ${b.length}`);
    }
    w.set(b, 0);
    return w;
  }
  if (ty.startsWith("uint")) {
    return encodeUint(ty, ty.slice(4), value);
  }
  if (ty.startsWith("int")) {
    return encodeInt(ty, ty.slice(3), value);
  }
  throw new KobeError("input", `unsupported EIP-712 type: ${ty}`);
}

function encodeUint(ty: string, bitsStr: string, value: unknown): Uint8Array {
  const bits = parseIntWidth(ty, bitsStr);
  const mag = parseUintBe(value);
  const first = mag.findIndex((b) => b !== 0);
  const magnitude = first === -1 ? new Uint8Array(0) : mag.subarray(first);
  const byteWidth = bits / 8;
  if (magnitude.length > byteWidth) {
    throw new KobeError("input", `${ty}: value exceeds ${bits}-bit range`);
  }
  const w = new Uint8Array(32);
  w.set(magnitude, 32 - magnitude.length);
  return w;
}

function encodeInt(ty: string, bitsStr: string, value: unknown): Uint8Array {
  const bits = parseIntWidth(ty, bitsStr);
  const { negative, magnitude } = parseIntMagnitude(value);
  checkIntRange(ty, bits, negative, magnitude);
  const w = new Uint8Array(32);
  w.set(
    magnitude.subarray(Math.max(0, magnitude.length - 32)),
    32 - Math.min(32, magnitude.length),
  );
  if (negative) {
    negateTwos(w);
  }
  return w;
}

function parseIntWidth(ty: string, bitsStr: string): number {
  const bits = Number(bitsStr);
  if (!Number.isInteger(bits) || bits === 0 || bits > 256 || bits % 8 !== 0) {
    throw new KobeError("input", `${ty}: bad integer width ${bitsStr}`);
  }
  return bits;
}

function parseUintBe(value: unknown): Uint8Array {
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0) {
      throw new KobeError("input", "uint must be non-negative integer");
    }
    return parseHex(value.toString(16).padStart(16, "0"));
  }
  if (typeof value === "string") {
    if (value.startsWith("0x") || value.startsWith("0X")) {
      return parseHex(value);
    }
    return parseDecimalBe(value);
  }
  throw new KobeError("input", "uint must be number or string");
}

function parseIntMagnitude(value: unknown): { negative: boolean; magnitude: Uint8Array } {
  if (typeof value === "number") {
    if (!Number.isInteger(value)) {
      throw new KobeError("input", "int must be integer");
    }
    return { negative: value < 0, magnitude: parseDecimalBe(String(Math.abs(value))) };
  }
  if (typeof value === "string") {
    if (value.startsWith("0x") || value.startsWith("0X")) {
      return { negative: false, magnitude: parseHex(value) };
    }
    if (value.startsWith("-")) {
      return { negative: true, magnitude: parseDecimalBe(value.slice(1)) };
    }
    if (value.startsWith("+")) {
      return { negative: false, magnitude: parseDecimalBe(value.slice(1)) };
    }
    return { negative: false, magnitude: parseDecimalBe(value) };
  }
  throw new KobeError("input", "int must be number or string");
}

function parseDecimalBe(s: string): Uint8Array {
  if (s.length === 0 || !/^\d+$/.test(s)) {
    throw new KobeError("input", `invalid integer literal: ${s}`);
  }
  let limbs = [0];
  for (const ch of s) {
    let carry = (ch.codePointAt(0) ?? 0) - 48;
    const next: number[] = [];
    for (const limb of limbs) {
      const v = limb * 10 + carry;
      next.push(v % 256);
      carry = Math.floor(v / 256);
    }
    while (carry > 0) {
      next.push(carry % 256);
      carry = Math.floor(carry / 256);
    }
    limbs = next;
  }
  limbs.reverse();
  const first = limbs.findIndex((b) => b !== 0);
  return Uint8Array.from(first === -1 ? [0] : limbs.slice(first));
}

function checkIntRange(ty: string, bits: number, negative: boolean, magnitude: Uint8Array): void {
  const bufLen = 33;
  if (magnitude.length > bufLen) {
    throw new KobeError("input", `${ty}: value exceeds ${bits}-bit signed range`);
  }
  const mag = new Uint8Array(bufLen);
  mag.set(magnitude, bufLen - magnitude.length);
  const threshold = new Uint8Array(bufLen);
  const hiBit = bits - 1;
  threshold[bufLen - 1 - Math.floor(hiBit / 8)] = 2 ** (hiBit % 8);
  // Equal-length lowercase hex strings compare in byte order.
  const magHex = bytesToHex(mag);
  const thresholdHex = bytesToHex(threshold);
  const cmp = magHex === thresholdHex ? 0 : magHex < thresholdHex ? -1 : 1;
  const fits = (!negative && cmp < 0) || (negative && cmp <= 0);
  if (!fits) {
    throw new KobeError("input", `${ty}: value exceeds ${bits}-bit signed range`);
  }
}

function negateTwos(bytes: Uint8Array): void {
  for (const [i, b] of bytes.entries()) {
    bytes[i] = 255 - b;
  }
  let carry = 1;
  for (let i = bytes.length - 1; i >= 0; i--) {
    const sum = (bytes[i] ?? 0) + carry;
    bytes[i] = sum % 256;
    carry = Math.floor(sum / 256);
  }
}
