/**
 * Host-packages-only subpath (design/entry.mdx): `connectKernel` wires a spawned kernel port into
 * the host-facing `Wallet`, and `PasskeyCeremony` is the platform's WebAuthn surface. Applications
 * must not use this subpath — it exists for `@qntx/wallet-worker` / `@qntx/wallet-native`.
 */
export { connectKernel } from "./wallet.ts";
export type { ConnectOptions } from "./wallet.ts";
export type { MainPort, SetTimer } from "./channel.ts";
export type { PasskeyCeremony, PrfResult, PrfSalts } from "./factors.ts";
