# AGENTS.md

- Do not preserve backward compatibility. Remove obsolete paths instead of adding compatibility layers, fallbacks, or migrations.
- Choose the simplest implementation that fully meets the current requirements. Avoid speculative abstractions, configuration, and indirection.
- Grow the system in layers. Start from the smallest version that works end to end, and add each new capability on top of a product that already works. Never trade a working product for unfinished complexity.
- Keep components modular and concerns clearly separated.
- Prefer established, well-maintained libraries when they reduce overall complexity or improve reliability. Do not reimplement common functionality without a clear reason.
- Lean on the dependencies already in the project before writing your own implementation or adding packages. Do not assume a library lacks a capability without checking its documentation and types.
- Make architectural decisions for the long term. Do not accept a stopgap that only works for now and is meant to be replaced later.

## Architecture invariants

- qntx/wallet composes qntx/nostr, qntx/spark and qntx/trust. It never reimplements
  protocol or cryptographic code that belongs to them.
- @qntx/wallet-kernel is private and only bundled by the host packages. Nothing in the
  main runtime can import it.
- Secrets (entropy, seed, private keys, DEK, PRF output) exist only in the enclave
  (Web Worker, RN kernel runtime). Messages carry no signing secrets, except user exports
  and the data key.
- The kernel source never imports -worker or -native packages; backends are injected by the
  host packages. The engine and @qntx/wallet never import signing implementations.
- Kernel code uses only the globals allowed in design/enclave.mdx; it must run in a bare
  Hermes runtime.
- Native capabilities that hold, produce or unwrap secrets (keystore, passkey, store) are
  injected into the kernel runtime as JSI host objects and are never registered with Nitro.
- Protocol library versions are pinned exactly and recorded in the kernel manifest;
  backends' abiVersion is checked at kernel start.
- Every vault, backup, template and protocol format has fixed vectors in vectors/.
- packages/*/src is platform-neutral; all I/O is injected; no ambient singletons.

`design/` is local-only and never committed.

## Commands

Local gate before a pull request:

```bash
bun run lint && bun run typecheck && bun run test
```
