/**
 * Serves the static test page through vite-plus's dev server (the brief's `optimizeDeps.exclude`
 * only exists on the dev server). The page imports `@qntx/wallet-wasm/browser` from the built dist,
 * and `new URL("kernel.worker.js", import.meta.url)` resolves against the served dist path.
 */
import { createServer } from "vite";

const server = await createServer({
  configFile: false,
  root: new URL("page", import.meta.url).pathname,
  optimizeDeps: { exclude: ["@qntx/wallet-wasm"] },
  server: {
    // localhost, not 127.0.0.1 — WebAuthn rejects IP literals as rpId ("invalid domain").
    host: "localhost",
    port: 4174,
    strictPort: true,
    headers: {
      "Content-Security-Policy":
        "default-src 'self'; script-src 'self'; worker-src 'self'; connect-src 'self'",
    },
  },
  logLevel: "warn",
});
await server.listen();
