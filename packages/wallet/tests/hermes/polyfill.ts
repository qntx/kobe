/**
 * What a React Native host installs before importing `@qntx/wallet`: Hermes has no
 * `Symbol.dispose`. `Symbol.for` matches the key that TypeScript, Babel and esbuild `using` helpers
 * fall back to. The smoke runner executes this as a separate script ahead of the bundle.
 */
const symbols = Symbol as { dispose?: symbol; asyncDispose?: symbol };
symbols.dispose ??= Symbol.for("Symbol.dispose");
symbols.asyncDispose ??= Symbol.for("Symbol.asyncDispose");

export const disposeSymbol: symbol = symbols.dispose;
