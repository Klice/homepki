# homepki — Spec

> Product-level specification. Describes *what* homepki is, the operator-facing
> feature set, and the deployment shape. Companion docs cover specific areas:
>
> - [LIFECYCLE.md](LIFECYCLE.md) — cert/key/CRL lifecycle behaviour.
> - [STORAGE.md](STORAGE.md) — database, schema, migrations, backup.
> - [API.md](API.md) — HTTP routes, request/response shapes, content types.
>
> Other implementation areas (deploy execution, web/UI internals) will get
> their own focused docs as they're built.

## Context

A small self-hosted web UI for managing a private self-signed PKI used to issue
TLS certificates for internal web apps. Off-the-shelf tools either assume a
public CA workflow (step-ca, smallstep, EJBCA) or are CLI-only (openssl, cfssl).
The goal is a single-binary, single-operator tool that makes it trivial to:
spin up a root CA, chain an intermediate beneath it, issue SAN-bearing leaf
certs for nginx/Caddy hosts, rotate them, and revoke via a CRL — without ever
shelling out to openssl.

**Out of scope by design:** ACME server, OCSP responder, external CSR signing,
multi-tenant access. These can be added later but bloat v1.

## Stack

- **Language:** Go (latest stable).
- **HTTP:** stdlib `net/http` with 1.22+ pattern routing — no chi/gorilla.
- **Templating:** `html/template` + htmx — no template codegen.
- **Codegen:** allowed where it materially reduces hand-written code
  or catches whole classes of bugs. Generated files are committed so
  `go build` requires no extra step. In use: `sqlc` for SQL → typed
  Go in `internal/store/`.
- **DB:** SQLite via `modernc.org/sqlite` (pure Go → `CGO_ENABLED=0` → static scratch image). See [STORAGE.md](STORAGE.md).
- **PKCS#12 export:** `software.sslmate.com/src/go-pkcs12` using `pkcs12.Modern.Encode` (AES-256, understood by openssl 3 / browsers).
- **CRL generation:** stdlib `crypto/x509.CreateRevocationList`.
- **Logging:** stdlib `log/slog` (JSON in container, text on TTY).
- **CSS:** [pico.css](https://picocss.com) classless — keeps templates clean.

## Deployment

- Multi-stage Dockerfile → static binary in `scratch` (or `gcr.io/distroless/static`).
- `docker-compose.yml` with one service, named volume for the SQLite file.
- Bind container port to `127.0.0.1:8080` on the host.
- `CRL_BASE_URL` (e.g., `https://certs.lan`) must be reachable by clients
  verifying certs — operator puts a reverse proxy (Caddy/nginx) in front
  exposing `/crl/*` publicly if certs are used outside the host.
- Deploy targets (writing cert/key files for consuming services) require the
  operator to bind-mount destination paths into the container.

## Feature set (v1)

- Issue + rotate **root CAs**.
- Issue + rotate **intermediate CAs** chained to a chosen root.
- Issue + rotate **leaf certs** with SANs (DNS + IP), `serverAuth` EKU.
- **Revoke** any cert with an RFC 5280 reason code (subset — see [LIFECYCLE.md §5.2](LIFECYCLE.md#52-supported-reasons)).
- **Public CRL distribution endpoint** per CA. The URL is baked into each
  issued cert's CRL Distribution Points extension at issuance.
- **PKCS#12 export** for leaf certs (cert + key + chain, password-protected).
- **Deploy targets** per leaf cert: write cert/key to one or more configured
  paths (with mode/owner and optional post-deploy command), automatically
  re-deploy on rotation.
- **Lock/unlock** with a master passphrase; the app starts locked at rest and
  refuses key-bearing operations until unlocked.

## Auth

- Single operator, local only.
- Master passphrase gates access to private-key operations. The app starts
  locked; the operator unlocks via the UI, or via `CM_PASSPHRASE` for
  unattended deployments.
- Locked state disables: issuance, rotation, revocation, key download, deploy.
  Public CRL serving and metadata browsing remain available.
- State-changing requests are CSRF-protected.
- Cryptographic mechanism (KDF, KEK/DEK, AEAD, memory hygiene) — see
  [LIFECYCLE.md §1–2](LIFECYCLE.md#1-locking-and-unlocking). HTTP encoding of
  the lock state (status codes, session cookie, CSRF wire form) — see
  [API.md §4](API.md#4-authentication-and-session).

## Data

- All persistent state lives in a **single SQLite file** under `CM_DATA_DIR`.
  Backup = copy the file. No external secrets manager, no separate key files.
- Private-key material is encrypted at rest; see
  [LIFECYCLE.md §2](LIFECYCLE.md#2-key-encryption).
- Database choice, full schema, migrations, backup procedure — see
  [STORAGE.md](STORAGE.md).

## HTTP surface

The full route table, request/response shapes, content types, status codes,
and CSRF/session details live in [API.md](API.md). At the product level:

- A single web UI (HTML + htmx, no JSON/REST in v1) that browsers and curl
  consume identically.
- Cert/key/CRL downloads are direct binary/PEM responses, not wrapped in JSON.
- The CRL distribution endpoint is **public and unauthenticated** — clients
  verifying issued certs must be able to fetch it without credentials.
- A liveness endpoint is exposed for container orchestrators.

## Configuration (env)

| var                     | default         | purpose                                                       |
| ----------------------- | --------------- | ------------------------------------------------------------- |
| `CM_LISTEN_ADDR`        | `:8080`         | bind address                                                  |
| `CM_DATA_DIR`           | `/data`         | directory containing the SQLite file                          |
| `CRL_BASE_URL`          | _required_      | embedded into CRL DP of issued certs                          |
| `CM_PASSPHRASE`         | _optional_      | unattended unlock; if unset, the app starts locked            |
| `CM_AUTO_LOCK_MINUTES`  | _unset_         | auto-lock idle timeout in minutes; unset/`0` disables         |
| `CM_LOG_FORMAT`         | `json`          | `json` or `text`                                              |

## Project layout

```
cmd/homepki/main.go
internal/
  config/      # env-driven config
  crypto/      # KDF, KEK/DEK, AEAD
  pki/         # issuance, CRL, p12, verification helpers
  store/       # *sql.DB, migrations, CRUD
  web/         # mux, middleware, handlers, templates render
  deploy/      # deploy-target execution (writes, reloads)
migrations/    # NNNN_*.up.sql files
templates/     # html/template files
static/        # htmx.min.js, pico.css
Dockerfile
docker-compose.yml
go.mod
```

## Verification

- **Unit:** in `internal/pki`, issue root → intermediate → leaf; build
  `*x509.CertPool` from root; `cert.Verify(...)` — assert success; assert
  failure with wrong DNS, expired, and revoked-via-CRL.
- **CRL round-trip:** `openssl crl -in out.crl -noout -text -CAfile root.pem`
  after revoking — assert exit 0 and revoked serial appears.
- **PKCS#12 round-trip:** `openssl pkcs12 -in bundle.p12 -info -passin pass:test`
  — assert chain + key extract; re-decode with `pkcs12.Decode` and compare DER
  bytes.
- **CRL DP baked in:** `openssl x509 -in leaf.pem -noout -ext crlDistributionPoints`
  — assert URL matches `CRL_BASE_URL`.
- **End-to-end with nginx:** compose adds an nginx service consuming a deployed
  `fullchain.pem` + `key.pem` on 8443; `curl --cacert root.pem
  https://localhost:8443/` returns 200. Wired as `make e2e`.
- **Manual:** import root into macOS keychain, hit nginx in Safari, confirm
  green lock.
