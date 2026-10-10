import {
  secretKeyFromBytes,
  secretKeyFromDerived,
  secretKeyFromHex,
  type DerivedSecretSource,
  type SecretKey32,
} from "../secret/secret-key32.ts";

/** Builds fromSecretKey/fromBytes/fromHex/fromDerived around a SecretKey32 constructor. */
export function signerFromSecret<T, A extends unknown[] = []>(
  create: (key: SecretKey32, ...args: A) => T,
) {
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
