# vectors/

Shared cross-language test vectors. Both the TypeScript tests (under
`packages/kobe/tests/`) and the Rust `kobe-*` crates must pass against the
same files, which makes byte-level parity checkable.

## Layout

```text
vectors/<area>/<name>.json    one file per capability, name = capability id
                              without the "<area>." prefix, dots as hyphens
vectors/<area>/<name>.<ext>   official external vectors keep their original
                              format (e.g. bip39/official.csv)
```

`scripts/parity/check.ts` asserts that every file here is referenced by at
least one capability in `parity.json`.

## Schema

JSON files share a single envelope:

```json
{
  "schema": 1,
  "capability": "core.example",
  "source": { "kind": "official", "name": "<upstream>" },
  "cases": []
}
```

- `schema` — envelope version, currently always `1`.
- `capability` — the `parity.json` capability id this file exercises.
- `source.kind` — `official` (upstream vector, verbatim), `reference`
  (produced by an independent reference implementation; record its name and
  version in `source`), or `generated` (frozen output of the producing
  implementation; `generator` names the producing script/package and
  `version` the package version that produced it).
- `cases` — always an array. Success cases carry inputs and expected outputs;
  failure cases carry an `error` field naming the expected error or a null
  expectation field (`output: null`). Runners branch on the case fields; a
  file may mix case shapes.
