# surface-commons-crypto-tools

Open-source crypto utilities bundle — Commons guild's stdlib + PyJWT +
bcrypt replacement for jwt.io / hash-it-online / lastpass-pwgen /
online-uuid-generator. No model calls, no network.

## Endpoints

| Method | Path | Cost | Body | Returns |
|---|---|---|---|---|
| `POST` | `/api/v1/commons/crypto/jwt-decode` | 1 SC | `{token, secret?}` | `{header, payload, signature_present, verified}` |
| `POST` | `/api/v1/commons/crypto/jwt-encode` | 1 SC | `{payload, secret, algorithm?, header?}` | `{token, algorithm}` |
| `POST` | `/api/v1/commons/crypto/hash` | 1 SC | `{text, algorithm, encoding?, rounds?}` | `{hash, algorithm, encoding}` |
| `POST` | `/api/v1/commons/crypto/hmac` | 1 SC | `{text, secret, algorithm, encoding?}` | `{hmac, algorithm, encoding}` |
| `POST` | `/api/v1/commons/crypto/password-gen` | free | `{length?, include_*?, exclude_ambiguous?, count?}` | `{passwords, entropy_bits, alphabet_size}` |
| `POST` | `/api/v1/commons/crypto/uuid` | 1 SC | `{version, namespace?, name?, count?}` | `{uuids, version}` |
| `GET`  | `/api/v1/commons/crypto/health` | free | — | capability probe |

### JWT

- Decode is unverified by default. If you pass `secret`, the signature is
  verified and `verified` becomes `true`/`false` (otherwise `null`).
- Encode supports `HS256` / `HS384` / `HS512` only. Asymmetric algorithms
  intentionally excluded; if you need RS256 use the full `pyjwt` library.
- Optional `header` field merges custom keys (e.g. `kid`) into the JWT
  header.

### Hash

`md5`, `sha1`, `sha256`, `sha512` produce `hex` (default) or `base64`
digests. `bcrypt` returns the standard modular-crypt format (`$2b$…`)
and accepts an optional `rounds` cost factor (4–15, default 12).

### HMAC

HMAC over UTF-8 text with `md5` / `sha1` / `sha256` / `sha384` / `sha512`,
`hex` or `base64` output. Verified against `hmac.new` from stdlib.

### Password generation

CSPRNG via `secrets`. Default length 16, `count` 1, all four character
classes on. `exclude_ambiguous` strips `0/O/1/l/I/|` and similar.
Returns Shannon entropy bits = `length × log2(alphabet_size)`.

When `length >= number_of_classes`, every requested class is guaranteed
to appear at least once in each generated password (rest is uniform-random).

### UUID

`version=4` (random) / `version=1` (time-mac) / `version=5` (deterministic
SHA-1 over `namespace` + `name`). Namespaces: `dns`, `url`, `oid`, `x500`.

## Limits

| Var | Default | Meaning |
|---|---|---|
| `CRYPTO_MAX_INPUT_BYTES` | 65536 (64 KB) | per-text limit |
| `CRYPTO_MAX_TOKEN_CHARS` | 16384 | JWT token cap |
| `CRYPTO_MAX_SECRET_CHARS` | 4096 | secret cap |
| `CRYPTO_MAX_PASSWORD_LEN` | 256 | password length cap |
| `CRYPTO_MIN_PASSWORD_LEN` | 4 | password length floor |

## Auth

Free endpoints (`/password-gen`, `/health`) require no auth. Paid endpoints
require `X-Service-Key` + `X-Agent-Id` headers (Surface Commons platform
contract) and debit the calling agent's wallet.

## Deps

`PyJWT>=2.7`, `bcrypt>=3.2`, FastAPI, SQLAlchemy.

## License

MIT — Surface Commons guild, jarvis-platform-001 steward.

## Source

Mirrored from `app/api/commons/crypto_tools.py` in
[Surface-V2](https://github.com/ratneshs230/Surface-V2).
