/**
 * Package check: the root entry (and every non-nostr subpath) must not pull @qntx/nostr at runtime
 * — the nostr module is the only chunk allowed to import it. Walks each entry's transitive relative
 * imports and fails if any reachable file references @qntx/nostr.
 */
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const dist = join(import.meta.dirname, "..", "dist");
const entries = ["index.mjs", "host.mjs", "protocol.mjs", "types.mjs"];
const visited = new Set<string>();
const offenders: string[] = [];

const visit = (file: string): void => {
  if (visited.has(file)) {
    return;
  }
  visited.add(file);
  const source = readFileSync(join(dist, file), "utf8");
  if (source.includes("@qntx/nostr")) {
    offenders.push(file);
  }
  for (const match of source.matchAll(/from\s+["'](\.[^"']+)["']/g)) {
    const [, spec] = match;
    if (spec !== undefined) {
      visit(spec.replace(/^\.\//, ""));
    }
  }
};

for (const entry of entries) {
  visit(entry);
}
// Every dist chunk is reachable from some entry; unknown leftovers get checked too.
for (const file of readdirSync(dist)) {
  if (file.endsWith(".mjs") && !visited.has(file) && file !== "nostr.mjs") {
    visit(file);
  }
}

if (offenders.length > 0) {
  console.error(`@qntx/nostr reachable from non-nostr entries: ${offenders.join(", ")}`);
  process.exitCode = 1;
} else {
  console.log(`check-nostr-free: ${visited.size} files clean`);
}
