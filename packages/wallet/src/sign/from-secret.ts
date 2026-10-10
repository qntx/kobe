import {
  secretKeyFromBytes,
  secretKeyFromDerived,
  secretKeyFromHex,
} from "../secret/secret-key32.ts";
import type { DerivedSecretSource, SecretKey32 } from "../secret/secret-key32.ts";

export type SignerKit<T, A extends unknown[] = never[]> = {
  fromSecretKey: (key: SecretKey32, ...args: A) => T;
  fromBytes: (bytes: Uint8Array, ...args: A) => T;
  fromHex: (hex: string, ...args: A) => T;
  fromDerived: (account: DerivedSecretSource, ...args: A) => T;
};

/** Builds fromSecretKey/fromBytes/fromHex/fromDerived around a SecretKey32 constructor. */
export function signerFromSecret<T, A extends unknown[] = never[]>(
  create: (key: SecretKey32, ...args: A) => T,
): SignerKit<T, A> {
  return {
    fromSecretKey: create,
    fromBytes(bytes: Uint8Array, ...args: A): T {
      using key = secretKeyFromBytes(bytes);
      return create(key, ...args);
    },
    fromHex(hex: string, ...args: A): T {
      using key = secretKeyFromHex(hex);
      return create(key, ...args);
    },
    fromDerived(account: DerivedSecretSource, ...args: A): T {
      using key = secretKeyFromDerived(account);
      return create(key, ...args);
    },
  };
}
