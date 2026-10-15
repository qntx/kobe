import type { CORE_METHODS, MethodName } from "@qntx/wallet/protocol";

import type { Handler } from "./context.ts";
import * as secretsCommands from "./secrets.ts";
import * as vaultCommands from "./vault.ts";
import * as walletCommands from "./wallets.ts";

/**
 * One typed entry per core protocol method; `ParamsOf`/`ResultOf` come from the METHODS validators,
 * so a handler whose shape drifts from the table fails to typecheck. kernel.ts composes this with
 * `status` (whose result validator composes every module) and each module's table.
 */
export const CORE_HANDLERS: {
  [M in keyof typeof CORE_METHODS & MethodName]: Handler<M>;
} = {
  "vault.unlock": async (ctx, params) => vaultCommands.unlockVault(ctx, params),
  "vault.lock": (ctx) => vaultCommands.lockVault(ctx),
  "vault.reset": async (ctx) => vaultCommands.resetVault(ctx),
  "vault.addFactor": async (ctx, params, session) => vaultCommands.addFactor(ctx, params, session),
  "vault.removeFactor": async (ctx, params, session) =>
    vaultCommands.removeFactor(ctx, params, session),
  "wallet.createWithPasskey": async (ctx, params, session) =>
    walletCommands.createWithPasskey(ctx, params, session),
  "wallet.restoreWithPasskey": async (ctx, params, session) =>
    walletCommands.createWithPasskey(ctx, params, session),
  "wallet.createMnemonic": async (ctx, params, session) =>
    walletCommands.createMnemonic(ctx, params, session),
  "wallet.confirmMnemonic": async (ctx, params) => walletCommands.confirmMnemonic(ctx, params),
  "wallet.discardMnemonic": (ctx, params) => walletCommands.discardMnemonic(ctx, params),
  "wallet.importMnemonic": async (ctx, params, session) =>
    walletCommands.importMnemonic(ctx, params, session),
  "wallet.delete": async (ctx, params, session) =>
    walletCommands.deleteWallet(ctx, params, session),
  "wallet.exportMnemonic": async (ctx, params, session) =>
    secretsCommands.exportMnemonic(ctx, params, session),
  "dataKeys.get": async (ctx, params, session) => secretsCommands.getDataKey(ctx, params, session),
};
