# Release checklist

1. CI green on `main` (`lint`, `test`, `deny`, `no_std`).
2. Local: `just all` (or equivalent fmt/clippy/deny/no_std) and `just test`.
3. `CHANGELOG.md` has a dated section for the version being tagged; no open **Breaking** bullets under `[Unreleased]` that belong in the release.
4. Workspace `version` and path deps match the tag (`3.0.0` → path `"3.0"`).
5. Tag and push: `git tag v3.0.0 && git push origin v3.0.0` (or push with `--tags`).
6. Confirm GitHub Actions `release.yml` and `publish.yml` succeed.
7. crates.io publish order is handled by the workflow: primitives → chain crates → `kobe` → `kobe-cli`.
