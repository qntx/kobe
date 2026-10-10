import { bytesToHex } from "../crypto/hex.ts";
import { SignError } from "../errors/sign.ts";

/** EIP-191 / EIP-712: add to raw v so wire is 27|28. */
export const EIP191_OFFSET = 27;

export type SignOutput =
  | {
      readonly scheme: "ecdsa_recoverable";
      readonly signature: Uint8Array;
      readonly v: number;
    }
  | { readonly scheme: "ecdsa_der"; readonly der: Uint8Array }
  | { readonly scheme: "ed25519"; readonly signature: Uint8Array }
  | {
      readonly scheme: "ed25519_with_pubkey";
      readonly signature: Uint8Array;
      readonly publicKey: Uint8Array;
    }
  | {
      readonly scheme: "schnorr";
      readonly signature: Uint8Array;
      readonly xonlyPublicKey: Uint8Array;
    };

/** Flatten to wire bytes. ECDSA recoverable → 65B signature||v. */
export function signOutputToBytes(out: SignOutput): Uint8Array {
  switch (out.scheme) {
    case "ecdsa_recoverable": {
      if (out.signature.length !== 64) {
        throw new SignError("invalid_signature", "ecdsa signature must be 64 bytes");
      }
      const wire = new Uint8Array(65);
      wire.set(out.signature, 0);
      wire[64] = out.v & 0xff;
      return wire;
    }
    case "ecdsa_der":
      return new Uint8Array(out.der);
    case "ed25519":
    case "ed25519_with_pubkey":
    case "schnorr":
      return new Uint8Array(out.signature);
  }
}

export function signOutputToHex(out: SignOutput): string {
  return bytesToHex(signOutputToBytes(out));
}

export function signOutputV(out: SignOutput): number | undefined {
  return out.scheme === "ecdsa_recoverable" ? out.v : undefined;
}

export function signOutputPublicKey(out: SignOutput): Uint8Array | undefined {
  if (out.scheme === "ed25519_with_pubkey") return new Uint8Array(out.publicKey);
  if (out.scheme === "schnorr") return new Uint8Array(out.xonlyPublicKey);
  return undefined;
}

/** ECDSA only: new output with `v' = (v + offset) & 0xff`. Others: identity. */
export function withVOffset(out: SignOutput, offset: number): SignOutput {
  if (out.scheme !== "ecdsa_recoverable") return out;
  return {
    scheme: "ecdsa_recoverable",
    signature: out.signature,
    v: (out.v + offset) & 0xff,
  };
}
