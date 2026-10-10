import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bech32, bech32m } from "@scure/base";
import { hash160 } from "../../crypto/index.ts";
import { DeriveError } from "../../errors/derive.ts";
import { base58check, base58checkEncode } from "./encoding.ts";
import type { BtcAddressType, BtcNetwork } from "./types.ts";

function hrp(network: BtcNetwork): "bc" | "tb" {
  return network === "mainnet" ? "bc" : "tb";
}

function requireCompressed(pk: Uint8Array): void {
  if (pk.length !== 33 || (pk[0] !== 0x02 && pk[0] !== 0x03)) {
    throw new DeriveError("crypto", "btc: expected compressed public key prefix 0x02 or 0x03");
  }
}

function taggedHash(tag: string, data: Uint8Array): Uint8Array {
  const t = sha256(new TextEncoder().encode(tag));
  const h = sha256.create();
  h.update(t);
  h.update(t);
  h.update(data);
  return h.digest();
}

export function btcAddressFromCompressed(
  publicKey: Uint8Array,
  network: BtcNetwork,
  addressType: BtcAddressType,
): string {
  requireCompressed(publicKey);
  switch (addressType) {
    case "p2pkh":
      return base58check(network === "mainnet" ? 0x00 : 0x6f, hash160(publicKey));
    case "p2sh-p2wpkh": {
      const redeem = new Uint8Array(22);
      redeem[0] = 0x00;
      redeem[1] = 0x14;
      redeem.set(hash160(publicKey), 2);
      return base58check(network === "mainnet" ? 0x05 : 0xc4, hash160(redeem));
    }
    case "p2wpkh":
      return bech32.encode(hrp(network), [0, ...bech32.toWords(hash160(publicKey))]);
    case "p2tr": {
      const even = new Uint8Array(publicKey);
      even[0] = 0x02;
      const P = secp256k1.Point.fromBytes(even);
      const tweakBytes = taggedHash("TapTweak", even.subarray(1));
      const t = secp256k1.Point.Fn.fromBytes(tweakBytes);
      const Q = P.add(secp256k1.Point.BASE.multiply(t));
      const outputX = Q.toBytes(true).subarray(1);
      return bech32m.encode(hrp(network), [1, ...bech32m.toWords(outputX)]);
    }
  }
}

export function encodeWif(privateKey: Uint8Array, network: BtcNetwork): string {
  if (privateKey.length !== 32) {
    throw new DeriveError("crypto", "btc: WIF requires 32-byte secret");
  }
  const body = new Uint8Array(34);
  body[0] = network === "mainnet" ? 0x80 : 0xef;
  body.set(privateKey, 1);
  body[33] = 0x01;
  return base58checkEncode(body);
}
