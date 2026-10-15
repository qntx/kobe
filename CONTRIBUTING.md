# Contributing

## Prerequisites

- **Bun 1.4** — package scripts, tests, and tooling.
- **Node >= 20.19** — the Node test host for the kernel.

## Repository layout

```text
packages/wallet-kernel/  @qntx/wallet-kernel — private kernel package
                         (secret, seed, derive, vault); only bundled by the
                         host packages, never published
vectors/                 fixed test vectors (see vectors/README.md)
scripts/                 repo tooling (check-version, vectors/)
```

Packages are created only when they have content: `@qntx/wallet` and
`@qntx/wallet-wasm` appear in later milestones.

## Local gate

Run before opening a pull request:

```bash
bun run lint && bun run typecheck && bun run test
```

## Commits

English Conventional Commits: `type(scope): subject` (`feat`, `fix`, `docs`,
`style`, `refactor`, `perf`, `test`, `chore`, `ci`, `build`, `revert`), subject
in imperative mood, no period, ≤ 50 chars; `BREAKING CHANGE:` footer for
breaking changes.

## Versioning and release

All packages under `packages/` share one lockstep version; `release` runs
`bumpp` (see `bump.config.ts`), which pushes a `release/vX.Y.Z` branch and
opens the release pull request via `gh`. After the release PR merges, tag the
merge commit and push the tag:

```sh
git tag -a vX.Y.Z <merge-sha> -m vX.Y.Z && git push origin vX.Y.Z
```

`scripts/check-version.ts` fails the lint gate when internal `@qntx/*` ranges
or `bun.lock` workspace entries drift from the manifests.

## License

Contributions are dual-licensed under MIT OR Apache-2.0.
