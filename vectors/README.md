# Vectors

Fixed test vectors for the kernel. **All data here is test-only — never use
it for funds.**

| File             | Contents                                                                                           | Provenance                                                                                                                            |
| ---------------- | -------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `bip39.json`     | Official BIP-39 english vectors (entropy, mnemonic, seed; passphrase `TREZOR`)                     | `curl -fsSL https://raw.githubusercontent.com/trezor/python-mnemonic/master/vectors.json`, `english` key kept verbatim                |
| `nip06.json`     | The two NIP-06 spec vectors: mnemonic → `m/44'/1237'/0'/0/0` private/public key (+ nsec/npub)      | Copied verbatim from https://github.com/nostr-protocol/nips/blob/master/06.md                                                          |
| `wallet-id.json` | BIP-32 test-vector-1 master public key → `walletId`                                                | Computed without project code: `{ printf 'qntx-wallet/wallet-id/v1'; printf '0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2' \| xxd -r -p; } \| shasum -a 256 \| cut -c1-16` |
| `factors.json`   | Password KEK (`PBKDF2-HMAC-SHA256` of the NFKC password, salt, 600000, 32) and passkey KEK (HKDF)  | Computed with `python3 hashlib.pbkdf2_hmac` and a hand-rolled HMAC HKDF; see below                                                    |
| `envelope.json`  | Fixed key/nonce/context/header → sealed envelope (record and factor contexts)                      | `bun scripts/vectors/envelope.ts` — spells the format out byte by byte, no kernel imports                                              |
| `passkey.json`   | PRF `00..1f` → entropy → mnemonic → seed → NIP-06 group 0 key → `walletId`                         | `bun scripts/vectors/passkey.ts` — uses the libraries directly, no kernel imports                                                      |
| `factor-wrap.json` | KEK → factor public key; fixed DEK/eph/nonce → factor wrap v2 `sealed` (`0x02 ‖ ephPk ‖ binding ‖ envelope`) | `bun scripts/vectors/factor-wrap.ts` — uses noble directly, no kernel imports |
| `records.json`     | Exact public-header texts (entropy, data-key, nostr-key all origins, both factors) and the vault meta object | `bun scripts/vectors/records.ts` — `JSON.stringify` in the documented key order, no kernel imports |
| `protocol.json`    | PROTOCOL_VERSION 1 request envelopes, ok/err responses and events (`{"$bytes": hex}` marks Uint8Array), plus near-miss rejects | `bun scripts/vectors/protocol.ts` — wire shapes spelled out literally, no `@qntx/wallet` imports |

## factor vectors

Password KEK (`vectors/factors.json` → `password[]`):

```bash
python3 - <<'EOF'
import hashlib, unicodedata
kek = hashlib.pbkdf2_hmac(
    "sha256",
    unicodedata.normalize("NFKC", "correct horse battery").encode("utf-8"),
    bytes.fromhex("00112233445566778899aabbccddeeff"),
    600000, 32,
)
print(kek.hex())
EOF
```

The second case contains U+FB01 ("ﬁ") so its NFKC form differs from the input.

Passkey KEK (`HKDF-SHA256(ikm = prf, salt = credentialId, info = "qntx-wallet/kek/passkey/v1", 32)`):

```bash
python3 - <<'EOF'
import hashlib, hmac
prf = bytes(range(32)); cred = bytes.fromhex("deadbeefcafe")
info = b"qntx-wallet/kek/passkey/v1"
prk = hmac.new(cred, prf, hashlib.sha256).digest()
print(hmac.new(prk, info + b"\x01", hashlib.sha256).hexdigest())
EOF
```
