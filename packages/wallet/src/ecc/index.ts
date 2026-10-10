export { ed25519PublicKey, ed25519Sign, ed25519Verify, isValidEd25519Secret } from "./ed25519.ts";
export {
  isValidSecp256k1Secret,
  secp256k1PublicKey,
  secp256k1SignPrehash,
  secp256k1SignPrehashDer,
  secp256k1VerifyPrehash,
  secp256k1VerifyPrehashDer,
} from "./secp256k1.ts";
