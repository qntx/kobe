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
    // packages/wallet is excluded while it holds the verbatim @qntx/wallet
    // kernel copy; the ignore is lifted in the adaptation commit.
    ignorePatterns: ["target/**", "packages/kobe/.hermes-smoke.iife.js", "packages/wallet/**"],
    jsPlugins: [{ name: "vite-plus", specifier: "vite-plus/oxlint-plugin" }],
    rules: {
      "vite-plus/prefer-vite-plus-imports": "error",
    },
    overrides: [
      {
        files: ["packages/kobe/scripts/**", "scripts/**"],
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
        // src/core is the leaf layer: it must not reach ../nostr or the
        // package root. Overrides replace the rule config, so the
        // platform-neutral restrictions are re-added explicitly.
        files: ["packages/kobe/src/core/**"],
        rules: {
          "eslint/no-restricted-imports": [
            "error",
            {
              paths: platformNeutralImports.paths,
              patterns: [
                ...platformNeutralImports.patterns,
                {
                  group: ["..", "../", "../index", "../index.ts", "../nostr", "../nostr/**"],
                  message: "core is the leaf layer (AGENTS.md layering)",
                },
              ],
            },
          ],
        },
      },
      {
        // src/vault may import only src/core (AGENTS.md layering).
        files: ["packages/kobe/src/vault/**"],
        rules: {
          "eslint/no-restricted-imports": [
            "error",
            {
              paths: platformNeutralImports.paths,
              patterns: [
                ...platformNeutralImports.patterns,
                {
                  group: ["..", "../", "../index", "../index.ts", "../nostr", "../nostr/**"],
                  message: "vault may only reach ../core (AGENTS.md layering)",
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
      // Verbatim @qntx/wallet kernel copy — lifted in the adaptation commit.
      "packages/wallet/**",
    ],
  },
  run: { cache: process.env["CI"] === undefined || process.env["CI"] === "" },
});

export default config;
