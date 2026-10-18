# Security Policy

kobe generates and handles mnemonic phrases and private keys. Please do not
report vulnerabilities in public issues.

Report a vulnerability by emailing **<x@qntx.org>** with:

- a description of the issue and its impact,
- steps to reproduce or a proof of concept,
- the affected versions and platforms.

We aim to acknowledge reports within 72 hours and will coordinate a fix and
disclosure timeline with you.

## Scope

kobe is an offline library and CLI: it performs no network access and writes
no files. Issues that matter here are key-material leaks (logs, `Debug`
output, memory that outlives its `Zeroizing` guard), incorrect derivation or
address encoding, and supply-chain problems in the dependency tree.
