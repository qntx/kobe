import { bech32m } from "@scure/base";
import { DeriveError } from "../../errors/derive.ts";

/** Spark BIP-32 purpose: last 3 bytes of SHA-256("spark") as u24. */
export const SPARK_PURPOSE = 8_797_555;

export type SparkNetwork = "mainnet" | "testnet" | "signet" | "regtest" | "local";

const HRP: Record<SparkNetwork, string> = {
  mainnet: "spark",
  testnet: "sparkt",
  signet: "sparks",
  regtest: "sparkrt",
  local: "sparkl",
};

/** Field 1, wire type 2 (length-delimited). */
const PROTO_TAG = 0x0a;
const COMPRESSED_PUBKEY_LEN = 33;

export function sparkHrp(network: SparkNetwork): string {
  return HRP[network];
}

export function sparkPath(index: number): string {
  return `m/${SPARK_PURPOSE}'/${index}'/0'`;
}

/**
 * `bech32m(HRP, 0x0a || 0x21 || compressed_pubkey)`.
 * @throws DeriveError crypto | address_encoding
 */
export function encodeSparkAddress(compressed: Uint8Array, network: SparkNetwork): string {
  if (compressed.length !== 33 || (compressed[0] !== 0x02 && compressed[0] !== 0x03)) {
    throw new DeriveError("crypto", "spark: expected 33-byte compressed secp256k1 public key");
  }
  const payload = new Uint8Array(2 + compressed.length);
  payload[0] = PROTO_TAG;
  payload[1] = COMPRESSED_PUBKEY_LEN;
  payload.set(compressed, 2);
  try {
    return bech32m.encode(sparkHrp(network), bech32m.toWords(payload));
  } catch (e) {
    throw new DeriveError(
      "address_encoding",
      e instanceof Error ? `spark bech32m: ${e.message}` : "spark bech32m",
      { cause: e },
    );
  }
}
