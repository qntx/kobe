/// <reference types="node" />
/**
 * Bundle every probe in apps/harness/probes/*.ts into a classic IIFE script (same approach as
 * packages/wallet-worker/scripts/hermes-smoke.ts), compile each to Hermes bytecode and emit the C++
 * byte arrays consumed by the V1Probe module.
 *
 * Hermesc is resolved from apps/harness/node_modules — hermes-compiler is a react-native dependency
 * there, so the bytecode always matches the app's Hermes runtime (hermesc 260318099.0.4 for RN
 * 0.88). The script fails early if `bun install` has not run inside apps/harness.
 *
 * Helpers without a top-level effect (share.ts) and type-only files (*.d.ts) are inputs, not
 * probes: probe files are every other *.ts under probes/.
 */
import { createHash } from "node:crypto";
import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// The repo does not depend on @types/bun; declare the used surface (same as
// packages/wallet-worker/scripts/hermes-smoke.ts).
type BunBuildOutput = {
  success: boolean;
  logs: ReadonlyArray<{ toString: () => string }>;
  outputs: ReadonlyArray<{ kind: string; text: () => Promise<string> }>;
};
declare const Bun: {
  build: (options: {
    entrypoints: string[];
    target: "browser";
    format: "iife";
  }) => Promise<BunBuildOutput>;
  spawnSync: (
    cmd: ReadonlyArray<string>,
    options: { stdout: "pipe"; stderr: "pipe" },
  ) => {
    exitCode: number;
    stdout: { toString: () => string };
    stderr: { toString: () => string };
  };
};

const root = fileURLToPath(new URL("..", import.meta.url));
const harness = resolve(root, "apps/harness");
const probesDir = resolve(harness, "probes");
const outDir = resolve(harness, "modules/v1-probe/cpp/generated");

const hermesc = (() => {
  const require = createRequire(resolve(harness, "package.json"));
  const packageJson = require.resolve("hermes-compiler/package.json");
  const platformDir =
    process.platform === "darwin"
      ? "osx-bin"
      : process.platform === "linux"
        ? "linux64-bin"
        : "win64-bin";
  const binary = resolve(
    dirname(packageJson),
    "hermesc",
    platformDir,
    process.platform === "win32" ? "hermesc.exe" : "hermesc",
  );
  return binary;
})();

// Provenance for V1_RESULT lines: commit/dirty from git, Nitro version from the installed
// package, the sha256 of the local bun patch, and the hermes-compiler version + `hermesc
// -version` banner.
const run = (cmd: string[]): string => {
  const proc = Bun.spawnSync(cmd, { stdout: "pipe", stderr: "pipe" });
  if (proc.exitCode !== 0) {
    throw new Error(`${cmd.join(" ")} failed (${proc.exitCode}): ${proc.stderr.toString()}`);
  }
  return proc.stdout.toString().trim();
};

const packageVersion = (require: NodeJS.Require, name: string): string => {
  const parsed: unknown = JSON.parse(readFileSync(require.resolve(`${name}/package.json`), "utf8"));
  if (
    typeof parsed === "object" &&
    parsed !== null &&
    "version" in parsed &&
    typeof parsed.version === "string"
  ) {
    return parsed.version;
  }
  throw new Error(`${name}/package.json carries no version`);
};

const provenance = (() => {
  const require = createRequire(resolve(harness, "package.json"));
  const nitroVersion = packageVersion(require, "react-native-nitro-modules");
  const hermescVersion = packageVersion(require, "hermes-compiler");
  const hermescBanner =
    run([hermesc, "-version"])
      .split("\n")
      .map((line) => line.trim())
      .find((line) => line.startsWith("Hermes")) ?? "unknown";
  const patchPath = resolve(harness, `patches/react-native-nitro-modules@${nitroVersion}.patch`);
  const nitroPatchSha256 = createHash("sha256").update(readFileSync(patchPath)).digest("hex");
  return {
    commit: run(["git", "-C", root, "rev-parse", "HEAD"]),
    dirty: run(["git", "-C", root, "status", "--porcelain"]).length > 0,
    nitroVersion,
    nitroPatchSha256,
    hermesc: `${hermescVersion} (${hermescBanner})`,
  };
})();

const probeFiles = readdirSync(probesDir)
  .filter((name) => name.endsWith(".ts") && name !== "share.ts" && !name.endsWith(".d.ts"))
  .toSorted();

if (probeFiles.length === 0) {
  throw new Error(`no probes found under ${probesDir}`);
}

const constName = (file: string): string =>
  `k${basename(file, ".ts")
    .split(/[^a-zA-Z0-9]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join("")}`;

const utf8 = (input: string): Uint8Array => new TextEncoder().encode(input);

const byteArray = (name: string, bytes: Uint8Array): string => {
  const lines: string[] = [`inline constexpr uint8_t ${name}[] = {`];
  for (let i = 0; i < bytes.length; i += 16) {
    lines.push(`  ${[...bytes.subarray(i, i + 16)].map(String).join(", ")},`);
  }
  lines.push("};");
  return lines.join("\n");
};

async function bundle(entrypoint: string): Promise<string> {
  const result = await Bun.build({
    entrypoints: [entrypoint],
    target: "browser",
    format: "iife",
  });
  if (!result.success) {
    for (const log of result.logs) {
      console.error(String(log));
    }
    throw new Error(`bun build failed for ${entrypoint}`);
  }
  const output = result.outputs.find((o) => o.kind === "entry-point");
  if (!output) {
    throw new Error(`bun build produced no entry-point output for ${entrypoint}`);
  }
  return output.text();
}

const compileBytecode = (source: string, workDir: string): Uint8Array => {
  const jsPath = resolve(workDir, `probe-${process.hrtime.bigint()}.js`);
  const hbcPath = jsPath.replace(/\.js$/, ".hbc");
  writeFileSync(jsPath, source);
  // -emit-async-break-check lets KernelRuntime.destroy() interrupt running JS
  // via IHermes::asyncTriggerTimeout; without it bytecode busy-loops cannot be
  // stopped (supported since hermesc 250829098).
  const proc = Bun.spawnSync(
    [hermesc, "-emit-binary", "-emit-async-break-check", "-out", hbcPath, jsPath],
    {
      stdout: "pipe",
      stderr: "pipe",
    },
  );
  if (proc.exitCode !== 0) {
    throw new Error(`hermesc failed (${proc.exitCode}): ${proc.stderr.toString()}`);
  }
  return new Uint8Array(readFileSync(hbcPath));
};

async function main(): Promise<number> {
  mkdirSync(outDir, { recursive: true });
  const sections: string[] = [
    "// Generated by scripts/harness-bundles.ts — do not edit.",
    "#pragma once",
    "",
    "#include <cstddef>",
    "#include <cstdint>",
    "",
    "namespace qntx::harness::probes {",
    "",
    "struct Script {",
    "  const uint8_t* source;",
    "  size_t sourceSize;",
    "  const uint8_t* bytecode;",
    "  size_t bytecodeSize;",
    "};",
    "",
    "// Provenance attached to every V1_RESULT line (HybridV1Probe.cpp).",
    `inline constexpr char kCommit[] = "${provenance.commit}";`,
    `inline constexpr bool kDirty = ${provenance.dirty ? "true" : "false"};`,
    `inline constexpr char kNitroVersion[] = "${provenance.nitroVersion}";`,
    `inline constexpr char kNitroPatchSha256[] = "${provenance.nitroPatchSha256}";`,
    `inline constexpr char kHermesc[] = "${provenance.hermesc}";`,
    "",
  ];
  const workDir = resolve(tmpdir(), `qntx-harness-bundles-${process.pid}`);
  mkdirSync(workDir, { recursive: true });
  try {
    const bundled = await Promise.all(
      probeFiles.map(async (file) => ({
        file,
        name: constName(file),
        source: await bundle(resolve(probesDir, file)),
      })),
    );
    for (const { file, name, source } of bundled) {
      const bytecode = compileBytecode(source, workDir);
      sections.push(
        `// probes/${file}`,
        byteArray(`${name}Source`, utf8(source)),
        byteArray(`${name}Bytecode`, bytecode),
        `inline const Script ${name}{${name}Source, sizeof(${name}Source), ${name}Bytecode, sizeof(${name}Bytecode)};`,
        "",
      );
      console.log(`${file}: source ${source.length} chars, bytecode ${bytecode.length} bytes`);
    }
  } finally {
    rmSync(workDir, { recursive: true, force: true });
  }
  sections.push("} // namespace qntx::harness::probes", "");
  writeFileSync(resolve(outDir, "probes.hpp"), sections.join("\n"));
  console.log(`wrote ${resolve(outDir, "probes.hpp")}`);
  return 0;
}

process.exitCode = await main();
