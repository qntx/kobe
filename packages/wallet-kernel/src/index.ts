/**
 * The kernel's surface for host packages: `startKernel` plus the injected-capability and
 * vault-store types the hosts implement, `createMemoryStore` for the Node host's store, and the
 * record-kind constraint every store validates. Everything else — vault/session/module internals —
 * is imported from `../src/...` by tests only; the package is private and bundled, never
 * published.
 */
export { KernelError } from "./errors.ts";
export type { KernelErrorCode } from "./errors.ts";
export { startKernel } from "./kernel.ts";
export type { KernelPlatform, KernelPolicy, Pbkdf2, Port, Random } from "./platform.ts";
export { createMemoryStore } from "./vault/memory.ts";
export { isRecordKind } from "./vault/store.ts";
export type {
  RecordStore,
  StoredFactor,
  StoredRecord,
  StoreOp,
  VaultImage,
  VaultMeta,
} from "./vault/store.ts";
