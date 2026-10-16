/**
 * Test-only globals installed before the kernel modules evaluate, for the raw Hermes CLI (`hermes`,
 * no RN host). Each shim mirrors what an Expo / React Native runtime provides in production — the
 * kernel documents these as injected platform capabilities, not fallbacks it owns. The module also
 * records which probed globals were absent before shimming; entry.ts prints the list so the smoke
 * run reports the bare-Hermes surface exactly.
 */

const has = (name: string): boolean => Reflect.get(globalThis, name) !== undefined;
const install = (name: string, value: unknown): void => {
  if (!has(name)) {
    Reflect.set(globalThis, name, value);
  }
};
const read = (name: string): unknown => Reflect.get(globalThis, name);

/** Referenced by entry.ts so bundlers keep this module (and its ordering). */
export const hermesGlobalsInstalled = true;

// Globals the kernel or its bundled dependencies may touch. The probe runs before any shim is
// installed, so this is the exact bare-Hermes surface — entry.ts prints it verbatim.
const PROBED = [
  "TextEncoder",
  "TextDecoder",
  "crypto",
  "queueMicrotask",
  "setTimeout",
  "setInterval",
  "URL",
  "URLSearchParams",
  "atob",
  "btoa",
  "Intl",
  "performance",
  "structuredClone",
  "FinalizationRegistry",
  "AbortController",
  "fetch",
  "indexedDB",
  "Buffer",
  "console",
] as const;

export const missingGlobals: ReadonlyArray<string> = [
  ...PROBED.filter((name) => !has(name)),
  ...(typeof "x".normalize === "function" ? [] : ["String.prototype.normalize"]),
];

export const shimmedGlobals: string[] = [];

// crypto.getRandomValues — production: react-native-quick-crypto / expo-crypto polyfill.
// The kernel's own entropy is injected through platform.random; this shim only feeds the
// library-internal draws the kernel cannot inject (schnorr aux, nip44 nonce). xorshift is
// test-grade only, not cryptographic.
install("crypto", {});
{
  const cryptoHost = read("crypto");
  if (
    typeof cryptoHost === "object" &&
    cryptoHost !== null &&
    typeof Reflect.get(cryptoHost, "getRandomValues") !== "function"
  ) {
    let state = 0x9e3779b9 ^ Date.now();
    const getRandomValues = <T extends { length: number; [k: number]: number }>(arr: T): T => {
      for (let i = 0; i < arr.length; i++) {
        state ^= state << 13;
        state ^= state >>> 17;
        state ^= state << 5;
        arr[i] = state >>> 0;
      }
      return arr;
    };
    Reflect.set(cryptoHost, "getRandomValues", getRandomValues);
    shimmedGlobals.push("crypto.getRandomValues");
  }
}

// TextDecoder — Hermes ships a native decoder as of 260318099 (RN 0.88); this
// shim only installs on older Hermes versions that lack it. The kernel decodes
// user secrets with { fatal: true }, so unlike the nostr.js harness this shim
// implements fatal mode: malformed input throws TypeError instead of silently
// producing U+FFFD.
const decodeFail = (): never => {
  throw new TypeError("The encoded data was not valid");
};
if (!has("TextDecoder")) {
  type DecodeOptions = { readonly stream?: boolean };
  class HermesTextDecoder {
    readonly encoding = "utf8";
    readonly fatal: boolean;
    readonly ignoreBOM = false;
    constructor(_label?: string, options?: { readonly fatal?: boolean }) {
      this.fatal = options?.fatal === true;
    }
    // oxlint-disable-next-line typescript/no-restricted-types -- decode(null) is part of the WebIDL signature
    decode(input?: ArrayBuffer | ArrayBufferView | null, _options?: DecodeOptions): string {
      if (input === undefined || input === null) {
        return "";
      }
      const bytes =
        input instanceof ArrayBuffer
          ? new Uint8Array(input)
          : new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
      const { fatal } = this;
      let out = "";
      let i = 0;
      while (i < bytes.length) {
        const b0 = bytes[i];
        if (b0 === undefined) {
          break;
        }
        if (b0 < 0x80) {
          out += String.fromCodePoint(b0);
          i += 1;
          continue;
        }
        // Sequence length and valid range for the second byte (the range also encodes the
        // overlong / surrogate / >U+10FFFF restrictions).
        let len: number;
        let lo = 0x80;
        let hi = 0xbf;
        if (b0 >= 0xc2 && b0 <= 0xdf) {
          len = 2;
        } else if (b0 === 0xe0) {
          len = 3;
          lo = 0xa0;
        } else if (b0 === 0xed) {
          len = 3;
          hi = 0x9f;
        } else if (b0 >= 0xe1 && b0 <= 0xef) {
          len = 3;
        } else if (b0 === 0xf0) {
          len = 4;
          lo = 0x90;
        } else if (b0 === 0xf4) {
          len = 4;
          hi = 0x8f;
        } else if (b0 >= 0xf1 && b0 <= 0xf3) {
          len = 4;
        } else {
          if (fatal) {
            decodeFail();
          }
          out += "�";
          i += 1;
          continue;
        }
        const b1 = bytes[i + 1];
        if (b1 === undefined || b1 < lo || b1 > hi) {
          if (fatal) {
            decodeFail();
          }
          out += "�";
          i += 1;
          continue;
        }
        let cp: number;
        if (len === 2) {
          cp = ((b0 & 0x1f) << 6) | (b1 & 0x3f);
        } else {
          const b2 = bytes[i + 2];
          if (b2 === undefined || b2 < 0x80 || b2 > 0xbf) {
            if (fatal) {
              decodeFail();
            }
            out += "�";
            i += 2;
            continue;
          }
          if (len === 3) {
            cp = ((b0 & 0x0f) << 12) | ((b1 & 0x3f) << 6) | (b2 & 0x3f);
          } else {
            const b3 = bytes[i + 3];
            if (b3 === undefined || b3 < 0x80 || b3 > 0xbf) {
              if (fatal) {
                decodeFail();
              }
              out += "�";
              i += 3;
              continue;
            }
            cp = ((b0 & 0x07) << 18) | ((b1 & 0x3f) << 12) | ((b2 & 0x3f) << 6) | (b3 & 0x3f);
          }
        }
        out += String.fromCodePoint(cp);
        i += len;
      }
      return out;
    }
  }
  Reflect.set(globalThis, "TextDecoder", HermesTextDecoder);
  shimmedGlobals.push("TextDecoder");
}
