import { builtinModules } from "node:module";

import { defineConfig } from "vite-plus";
import type { UserConfig } from "vite-plus";

import { fmt } from "@qntx/oxfmt";
import { config as lintConfig, merge } from "@qntx/oxlint";

// The library runs on Node, browsers, and Hermes: Node builtins must not be
// imported from src.
const platformNeutralImports = {
  paths: builtinModules.map((name) => ({
    name,
    message: "Node builtin — the library must stay platform-neutral",
  })),
  patterns: [
    {
      group: ["node:*"],
      message: "Node builtin — the library must stay platform-neutral",
    },
  ],
};

const config: UserConfig = defineConfig({
  staged: {
    "*": "vp check --fix",
  },
  test: {
    include: ["scripts/**/*.test.ts"],
  },
  lint: merge(lintConfig, {
    // merge() concatenates arrays onto the preset's own ignorePatterns.
    ignorePatterns: ["target/**", "packages/wallet/.hermes-smoke.iife.js"],
    jsPlugins: [{ name: "vite-plus", specifier: "vite-plus/oxlint-plugin" }],
    rules: {
      "vite-plus/prefer-vite-plus-imports": "error",
    },
    overrides: [
      {
        // Kernel src keeps its upstream interface style; bitwise ops are
        // inherent to BIP-39/ECC/RLP byte code.
        files: ["packages/wallet/src/**"],
        rules: {
          "typescript/method-signature-style": "off",
          "eslint/no-bitwise": "off",
        },
      },
      {
        // Table-driven KATs and JSON fixtures.
        files: ["packages/wallet/tests/**"],
        rules: {
          "vitest/no-conditional-expect": "off",
          "vitest/no-conditional-in-test": "off",
          "vitest/prefer-strict-equal": "off",
          "vitest/require-to-throw-message": "off",
          "typescript/no-non-null-assertion": "off",
          "typescript/no-unsafe-type-assertion": "off",
        },
      },
      {
        files: ["packages/wallet/scripts/**", "scripts/**"],
        rules: {
          // Maintenance scripts print their results.
          "eslint/no-console": "off",
        },
      },
      {
        files: ["packages/*/src/**"],
        rules: {
          // Hermes V1 (what React Native ships) has no ES2023 immutable array
          // methods, so the library must sort/reverse copies in place.
          "unicorn/no-array-sort": "off",
          "unicorn/no-array-reverse": "off",
          // @types/node leaks into the src program via platform files, so
          // Node-only globals would typecheck silently; browser-only globals
          // are equally absent on Hermes. Both sets are banned — library code
          // must use globalThis lookups instead.
          "eslint/no-restricted-globals": [
            "error",
            { name: "Buffer", message: "Node-only global — use Uint8Array" },
            { name: "process", message: "Node-only global — not available in browsers or Hermes" },
            { name: "global", message: "Node-only global — use globalThis" },
            { name: "require", message: "CJS-only — use import" },
            { name: "module", message: "CJS-only global" },
            { name: "__dirname", message: "CJS-only global" },
            { name: "__filename", message: "CJS-only global" },
            { name: "setImmediate", message: "Node-only global — use setTimeout" },
            { name: "clearImmediate", message: "Node-only global — use clearTimeout" },
            { name: "window", message: "browser-only global — use globalThis" },
            { name: "document", message: "browser-only global — use globalThis" },
            { name: "navigator", message: "browser-only global — use globalThis" },
            { name: "location", message: "browser-only global — use globalThis" },
            { name: "localStorage", message: "browser-only global — inject a store" },
            { name: "sessionStorage", message: "browser-only global — inject a store" },
          ],
          "eslint/no-restricted-imports": ["error", platformNeutralImports],
        },
      },
      {
        // The wallet foundation modules (hd/bip32/slip10/ecc/crypto/errors/
        // secret/sign) must not reach chains or vault — chains/vault build on
        // the foundation, never the reverse. Overrides replace the rule
        // config, so the platform-neutral restrictions are re-added explicitly.
        files: [
          "packages/wallet/src/hd/**",
          "packages/wallet/src/bip32/**",
          "packages/wallet/src/slip10/**",
          "packages/wallet/src/ecc/**",
          "packages/wallet/src/crypto/**",
          "packages/wallet/src/errors/**",
          "packages/wallet/src/secret/**",
          "packages/wallet/src/sign/**",
        ],
        rules: {
          "eslint/no-restricted-imports": [
            "error",
            {
              paths: platformNeutralImports.paths,
              patterns: [
                ...platformNeutralImports.patterns,
                {
                  group: [
                    "../chains",
                    "../chains/**",
                    "../../chains",
                    "../../chains/**",
                    "../vault",
                    "../vault/**",
                    "../../vault",
                    "../../vault/**",
                  ],
                  message:
                    "foundation modules must not import chains or vault (AGENTS.md layering)",
                },
              ],
            },
          ],
        },
      },
    ],
  }),
  fmt: {
    ...fmt,
    ignorePatterns: [
      ...fmt.ignorePatterns,
      "target/**",
      "bun.lock",
      // TOML is owned by taplo (.taplo.toml, align_entries); generated vectors
      // stay byte-frozen.
      "**/*.toml",
      "vectors/**",
    ],
  },
  run: { cache: process.env["CI"] === undefined || process.env["CI"] === "" },
});

export default config;
