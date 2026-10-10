import { hexToBytes } from "../../crypto/hex.ts";
import { keccak256 } from "../../crypto/index.ts";
import { SignError } from "../../errors/sign.ts";

type TypeField = { name: string; type: string };
type TypeDefs = Map<string, TypeField[]>;

export function hashTypedDataJson(json: string): Uint8Array {
  let v: unknown;
  try {
    v = JSON.parse(json) as unknown;
  } catch (e) {
    throw new SignError("invalid_message", e instanceof Error ? e.message : "invalid JSON", {
      cause: e,
    });
  }
  if (v === null || typeof v !== "object") {
    throw new SignError("invalid_message", "typed data must be an object");
  }
  const rec = v as Record<string, unknown>;
  if (!rec.types || typeof rec.types !== "object") {
    throw new SignError("invalid_message", "missing 'types'");
  }
  if (typeof rec.primaryType !== "string") {
    throw new SignError("invalid_message", "missing 'primaryType'");
  }
  if (!rec.domain || typeof rec.domain !== "object") {
    throw new SignError("invalid_message", "missing 'domain'");
  }
  if (!rec.message || typeof rec.message !== "object") {
    throw new SignError("invalid_message", "missing 'message'");
  }
  const types = parseTypes(rec.types);
  const domainHash = hashStruct("EIP712Domain", rec.domain, types);
  const messageHash = hashStruct(rec.primaryType, rec.message, types);
  const buf = new Uint8Array(2 + 32 + 32);
  buf[0] = 0x19;
  buf[1] = 0x01;
  buf.set(domainHash, 2);
  buf.set(messageHash, 34);
  return keccak256(buf);
}

function parseTypes(val: unknown): TypeDefs {
  if (val === null || typeof val !== "object") {
    throw new SignError("invalid_message", "'types' must be object");
  }
  const types: TypeDefs = new Map();
  for (const [name, fields] of Object.entries(val as Record<string, unknown>)) {
    if (!Array.isArray(fields)) {
      throw new SignError("invalid_message", `${name}: expected array`);
    }
    const parsed: TypeField[] = [];
    for (const f of fields) {
      if (f === null || typeof f !== "object") {
        throw new SignError("invalid_message", "field missing 'name'");
      }
      const o = f as Record<string, unknown>;
      if (typeof o.name !== "string" || typeof o.type !== "string") {
        throw new SignError("invalid_message", "field missing 'name' or 'type'");
      }
      parsed.push({ name: o.name, type: o.type });
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
  return keccak256(buf);
}

function typeHash(typeName: string, types: TypeDefs): Uint8Array {
  return keccak256(new TextEncoder().encode(encodeType(typeName, types)));
}

function encodeType(typeName: string, types: TypeDefs): string {
  const fields = types.get(typeName);
  if (!fields) throw new SignError("invalid_message", `unknown type: ${typeName}`);
  const deps = new Set<string>();
  collectDeps(typeName, types, deps);
  deps.delete(typeName);
  let result = formatStruct(typeName, fields);
  for (const dep of [...deps].toSorted()) {
    const f = types.get(dep);
    if (f) result += formatStruct(dep, f);
  }
  return result;
}

function formatStruct(name: string, fields: TypeField[]): string {
  return `${name}(${fields.map((f) => `${f.type} ${f.name}`).join(",")})`;
}

function collectDeps(typeName: string, types: TypeDefs, out: Set<string>): void {
  const fields = types.get(typeName);
  if (!fields) return;
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
  if (!fields) throw new SignError("invalid_message", `unknown type: ${typeName}`);
  if (data === null || typeof data !== "object") {
    throw new SignError("invalid_message", `expected object for ${typeName}`);
  }
  const obj = data as Record<string, unknown>;
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
      throw new SignError("invalid_message", `expected array for ${typeName}`);
    }
    const inner = new Uint8Array(value.length * 32);
    let o = 0;
    for (const item of value) {
      inner.set(encodeValue(base, item, types), o);
      o += 32;
    }
    return keccak256(inner);
  }
  if (types.has(typeName)) return hashStruct(typeName, value, types);
  return encodeAtomic(typeName, value);
}

function encodeAtomic(ty: string, value: unknown): Uint8Array {
  const w = new Uint8Array(32);
  if (ty === "address") {
    if (typeof value !== "string") {
      throw new SignError("invalid_message", "address must be string");
    }
    const b = hexToBytes(value);
    if (b.length !== 20) {
      throw new SignError("invalid_message", `address: expected 20 bytes, got ${b.length}`);
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
      throw new SignError("invalid_message", "string must be string");
    }
    return keccak256(new TextEncoder().encode(value));
  }
  if (ty === "bytes") {
    if (typeof value !== "string") {
      throw new SignError("invalid_message", "bytes must be hex string");
    }
    return keccak256(hexToBytes(value));
  }
  if (ty.startsWith("bytes") && ty.length > 5) {
    const n = Number(ty.slice(5));
    if (!Number.isInteger(n) || n < 1 || n > 32) {
      throw new SignError("invalid_message", "bytesN: N must be 1..32");
    }
    if (typeof value !== "string") {
      throw new SignError("invalid_message", `${ty} must be hex string`);
    }
    const b = hexToBytes(value);
    if (b.length !== n) {
      throw new SignError("invalid_message", `${ty}: expected ${n} bytes, got ${b.length}`);
    }
    w.set(b, 0);
    return w;
  }
  if (ty.startsWith("uint")) return encodeUint(ty, ty.slice(4), value);
  if (ty.startsWith("int")) return encodeInt(ty, ty.slice(3), value);
  throw new SignError("invalid_message", `unsupported EIP-712 type: ${ty}`);
}

function encodeUint(ty: string, bitsStr: string, value: unknown): Uint8Array {
  const bits = parseIntWidth(ty, bitsStr);
  const mag = parseUintBe(value);
  const first = mag.findIndex((b) => b !== 0);
  const magnitude = first === -1 ? new Uint8Array(0) : mag.subarray(first);
  const byteWidth = bits / 8;
  if (magnitude.length > byteWidth) {
    throw new SignError("invalid_message", `${ty}: value exceeds ${bits}-bit range`);
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
  if (negative) negateTwos(w);
  return w;
}

function parseIntWidth(ty: string, bitsStr: string): number {
  const bits = Number(bitsStr);
  if (!Number.isInteger(bits) || bits === 0 || bits > 256 || bits % 8 !== 0) {
    throw new SignError("invalid_message", `${ty}: bad integer width ${bitsStr}`);
  }
  return bits;
}

function parseUintBe(value: unknown): Uint8Array {
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0) {
      throw new SignError("invalid_message", "uint must be non-negative integer");
    }
    return hexToBytes(value.toString(16).padStart(16, "0"));
  }
  if (typeof value === "string") {
    if (value.startsWith("0x") || value.startsWith("0X")) return hexToBytes(value);
    return parseDecimalBe(value);
  }
  throw new SignError("invalid_message", "uint must be number or string");
}

function parseIntMagnitude(value: unknown): { negative: boolean; magnitude: Uint8Array } {
  if (typeof value === "number") {
    if (!Number.isInteger(value)) {
      throw new SignError("invalid_message", "int must be integer");
    }
    return { negative: value < 0, magnitude: parseDecimalBe(String(Math.abs(value))) };
  }
  if (typeof value === "string") {
    if (value.startsWith("0x") || value.startsWith("0X")) {
      return { negative: false, magnitude: hexToBytes(value) };
    }
    if (value.startsWith("-")) return { negative: true, magnitude: parseDecimalBe(value.slice(1)) };
    if (value.startsWith("+"))
      return { negative: false, magnitude: parseDecimalBe(value.slice(1)) };
    return { negative: false, magnitude: parseDecimalBe(value) };
  }
  throw new SignError("invalid_message", "int must be number or string");
}

function parseDecimalBe(s: string): Uint8Array {
  if (s.length === 0 || !/^\d+$/.test(s)) {
    throw new SignError("invalid_message", `invalid integer literal: ${s}`);
  }
  const limbs = [0];
  for (const ch of s) {
    let carry = ch.charCodeAt(0) - 48;
    for (let i = 0; i < limbs.length; i++) {
      const v = limbs[i]! * 10 + carry;
      limbs[i] = v & 0xff;
      carry = v >> 8;
    }
    while (carry) {
      limbs.push(carry & 0xff);
      carry >>= 8;
    }
  }
  limbs.reverse();
  const first = limbs.findIndex((b) => b !== 0);
  return Uint8Array.from(first === -1 ? [0] : limbs.slice(first));
}

function checkIntRange(ty: string, bits: number, negative: boolean, magnitude: Uint8Array): void {
  const bufLen = 33;
  if (magnitude.length > bufLen) {
    throw new SignError("invalid_message", `${ty}: value exceeds ${bits}-bit signed range`);
  }
  const mag = new Uint8Array(bufLen);
  mag.set(magnitude, bufLen - magnitude.length);
  const threshold = new Uint8Array(bufLen);
  const hiBit = bits - 1;
  threshold[bufLen - 1 - Math.floor(hiBit / 8)] = 1 << (hiBit % 8);
  let cmp = 0;
  for (let i = 0; i < bufLen; i++) {
    if (mag[i]! !== threshold[i]!) {
      cmp = mag[i]! < threshold[i]! ? -1 : 1;
      break;
    }
  }
  const fits = (!negative && cmp < 0) || (negative && cmp <= 0);
  if (!fits) {
    throw new SignError("invalid_message", `${ty}: value exceeds ${bits}-bit signed range`);
  }
}

function negateTwos(bytes: Uint8Array): void {
  for (let i = 0; i < bytes.length; i++) bytes[i] = ~bytes[i]! & 0xff;
  let carry = 1;
  for (let i = bytes.length - 1; i >= 0; i--) {
    const sum = bytes[i]! + carry;
    bytes[i] = sum & 0xff;
    carry = sum >> 8;
  }
}
