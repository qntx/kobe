import { bech32 } from "@scure/base";
import { hash160 } from "../../crypto/index.ts";
import { SignError } from "../../errors/sign.ts";
import { DeriveError } from "../../errors/derive.ts";

export function cosmosAddressFromCompressed(publicKey: Uint8Array, hrp: string): string {
  if (publicKey.length !== 33 || (publicKey[0] !== 0x02 && publicKey[0] !== 0x03)) {
    throw new DeriveError("crypto", "cosmos: expected compressed secp256k1 public key");
  }
  try {
    return bech32.encode(hrp, bech32.toWords(hash160(publicKey)));
  } catch (e) {
    throw new DeriveError(
      "address_encoding",
      e instanceof Error ? `cosmos bech32: ${e.message}` : "cosmos bech32 encoding",
      { cause: e },
    );
  }
}

/** Identity helper for signers; invalid HRP → SignError. */
export function cosmosAddressWithHrp(publicKey: Uint8Array, hrp: string): string {
  try {
    return cosmosAddressFromCompressed(publicKey, hrp);
  } catch (e) {
    if (e instanceof DeriveError && e.code === "address_encoding") {
      throw new SignError("invalid_message", e.message, { cause: e });
    }
    throw e;
  }
}
