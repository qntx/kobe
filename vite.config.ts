import { builtinModules } from "node:module";

import { defineConfig } from "vite-plus";
import type { UserConfig } from "vite-plus";

import { fmt } from "@qntx/oxfmt";
import { config as lintConfig, merge } from "@qntx/oxlint";

// The kernel runs on Node, browsers, and a bare Hermes runtime: Node builtins
// must not be imported from src.
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

// One-directional layer graph for packages/wallet-kernel/src — mirrors
// AGENTS.md "Architecture invariants". Each layer is a directory; the root
// files platform.ts and errors.ts are leaves importable by every layer.
// Later milestones extend this object (session, nostr, commands, kernel).
const KERNEL_SRC = "packages/wallet-kernel/src";
const LAYERS = {
  secret: [],
  seed: ["secret"],
  derive: ["secret"],
  vault: ["secret"],
  session: ["secret", "vault"],
  nostr: ["secret"],
  commands: ["secret", "seed", "derive", "vault", "session", "nostr"],
} as const;

const LAYER_NAMES = Object.keys(LAYERS).filter(
  (name): name is keyof typeof LAYERS => name in LAYERS,
);

// Relative import specifiers that would reach the package-root index from a
// layer file. src/ layers are flat directories, so every cross-layer import
// is a single `../` hop.
const PACKAGE_ROOT = ["..", "../", "../index", "../index.ts"];

// eslint/no-restricted-imports options that forbid a layer from importing any
// layer outside its allow list or the package root. The platform-neutral and
// kernel-boundary restrictions still apply on top: oxlint replaces (not
// merges) a rule's config per override, so callers must combine the patterns
// themselves.
function layerImports(layer: keyof typeof LAYERS) {
  const allowed: ReadonlyArray<string> = LAYERS[layer];
  const message =
    allowed.length > 0
      ? `${layer} may only import ${allowed.join(", ")} (AGENTS.md layering)`
      : `${layer} is the leaf layer (AGENTS.md layering)`;
  const forbidden = LAYER_NAMES.filter((name) => name !== layer && !allowed.includes(name));
  return {
    paths: [],
    patterns: [
      {
        group: [...PACKAGE_ROOT, ...forbidden.flatMap((name) => [`../${name}`, `../${name}/**`])],
        message,
      },
    ],
  };
}

// The kernel never imports the host-facing package, the chatty parts of
// @qntx/nostr, or any backend package — backends are injected by the hosts.
const kernelBoundaryImports = {
  paths: [],
  patterns: [
    {
      group: ["@qntx/wallet", "@qntx/wallet/**", "!@qntx/wallet/protocol", "!@qntx/wallet/types"],
      message:
        "the kernel may only import @qntx/wallet/protocol and @qntx/wallet/types — never the host entry",
    },
    {
      group: ["@qntx/nostr/client", "@qntx/nostr/relay", "@qntx/nostr/store"],
      message: "the kernel uses only the core, nips and signer parts of @qntx/nostr",
    },
    {
      group: ["@qntx/*-wasm", "@qntx/*-native"],
      message: "backends are injected by the host packages, never imported by the kernel",
    },
  ],
};

// Node-only and browser-only globals are both absent on Hermes; library code
// must use globalThis lookups instead. Kept as a const so the kernel override
// can extend it.
const platformNeutralGlobals = [
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
];

type OxlintOverride = (typeof lintConfig)["overrides"][number];

// Layer overrides replace the platform-neutral config rather than merging
// into it, so each one re-adds the other restrictions explicitly.
const kernelLayerOverrides: OxlintOverride[] = LAYER_NAMES.map((layer) => ({
  files: [`${KERNEL_SRC}/${layer}/**`],
  rules: {
    "eslint/no-restricted-imports": [
      "error",
      {
        paths: platformNeutralImports.paths,
        patterns: [
          ...platformNeutralImports.patterns,
          ...kernelBoundaryImports.patterns,
          ...layerImports(layer).patterns,
        ],
      },
    ],
  },
}));

const config: UserConfig = defineConfig({
  staged: {
    "*": "vp check --fix",
  },
  test: {
    include: ["scripts/**/*.test.ts"],
  },
  lint: merge(lintConfig, {
    // merge() concatenates arrays onto the preset's own ignorePatterns.
    // crates/, target/ and .vite-hooks/ are ignored leftovers from the
    // pre-reset repository.
    ignorePatterns: ["crates/**", "target/**", ".vite-hooks/**", "vectors/**"],
    jsPlugins: [{ name: "vite-plus", specifier: "vite-plus/oxlint-plugin" }],
    rules: {
      "vite-plus/prefer-vite-plus-imports": "error",
    },
    overrides: [
      {
        files: ["scripts/**", "packages/wallet-wasm/scripts/**"],
        rules: {
          // Maintenance scripts print their results.
          "eslint/no-console": "off",
        },
      },
      {
        files: ["packages/wallet-kernel/tests/**", "packages/wallet-wasm/tests/hermes/**"],
        rules: {
          // The seeded PRNG (mulberry32) and the Hermes UTF-8/xorshift shims are integer
          // arithmetic on purpose.
          "eslint/no-bitwise": "off",
        },
      },
      {
        files: ["packages/*/src/**"],
        rules: {
          // Hermes V1 (what React Native ships) has no ES2023 immutable array
          // methods, so the library must sort/reverse copies in place.
          "unicorn/no-array-sort": "off",
          "unicorn/no-array-reverse": "off",
          "eslint/no-restricted-globals": ["error", ...platformNeutralGlobals],
          "eslint/no-restricted-imports": ["error", platformNeutralImports],
        },
      },
      {
        // Bare Hermes has no ambient timers; Session receives them through
        // platform.setTimer instead. Overrides replace the rule config, so
        // the platform-neutral globals are repeated here.
        files: [`${KERNEL_SRC}/**`],
        rules: {
          "eslint/no-restricted-globals": [
            "error",
            ...platformNeutralGlobals,
            { name: "setTimeout", message: "no ambient timers — inject platform.setTimer" },
            { name: "clearTimeout", message: "no ambient timers — use the setTimer cancel" },
            { name: "setInterval", message: "no ambient timers — inject platform.setTimer" },
            { name: "clearInterval", message: "no ambient timers — use the setTimer cancel" },
          ],
        },
      },
      ...kernelLayerOverrides,
      {
        // The memory store implements the async RecordStore contract
        // synchronously; the async signature stays without an await.
        files: ["packages/wallet-kernel/src/vault/memory.ts"],
        rules: {
          "typescript/require-await": "off",
        },
      },
      {
        // The browser host entry, the browser worker entry and the IndexedDB
        // store ARE browser code — Web globals are allowed there, while the
        // Node/CJS-only names stay banned. Everywhere else keeps the full
        // platform-neutral list, including the kernel.
        files: [
          "packages/wallet-wasm/src/browser/**",
          "packages/wallet-wasm/src/worker/browser.ts",
          "packages/wallet-wasm/src/worker/indexeddb.ts",
        ],
        rules: {
          "eslint/no-restricted-globals": [
            "error",
            ...platformNeutralGlobals.filter(
              (entry) =>
                ![
                  "window",
                  "document",
                  "navigator",
                  "location",
                  "localStorage",
                  "sessionStorage",
                ].includes(entry.name),
            ),
          ],
        },
      },
      {
        // The Node host entry and its worker bundle ARE Node code — the only
        // builtin they may touch is worker_threads. The store wire (shared.ts,
        // store-client.ts, subtle.ts) stays platform-neutral for the W4 browser
        // worker.
        files: ["packages/wallet-wasm/src/node/**", "packages/wallet-wasm/src/worker/node.ts"],
        rules: {
          "eslint/no-restricted-imports": [
            "error",
            {
              paths: platformNeutralImports.paths.filter(
                (entry) => entry.name !== "worker_threads",
              ),
              patterns: [
                {
                  group: ["node:*", "!node:worker_threads"],
                  message: "Node builtin — only node:worker_threads is allowed in the Node host",
                },
              ],
            },
          ],
        },
      },
      {
        // Kernel root files (index.ts, platform.ts, errors.ts) compose or
        // feed the layers; the package boundary still applies.
        files: [`${KERNEL_SRC}/*.ts`],
        rules: {
          "eslint/no-restricted-imports": [
            "error",
            {
              paths: platformNeutralImports.paths,
              patterns: [...platformNeutralImports.patterns, ...kernelBoundaryImports.patterns],
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
      "crates/**",
      "target/**",
      ".vite-hooks/**",
      "bun.lock",
      "**/*.toml",
      // Generated vectors stay byte-frozen.
      "vectors/**",
    ],
  },
  run: { cache: process.env["CI"] === undefined || process.env["CI"] === "" },
});

export default config;
