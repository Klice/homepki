# homepki

A small self-hosted web UI for managing a private TLS PKI for internal web
apps. Single binary, single SQLite file, single operator. Spin up a root CA,
chain an intermediate beneath it, issue SAN-bearing leaf certs for
nginx/Caddy hosts, rotate them, revoke via CRL, and deploy keypairs to
configured paths — without ever shelling out to `openssl`.

> **Status: design phase.** No code yet. The `docs/` folder holds the v1
> spec set; `mockups/` holds the static HTML the UI is being designed
> against.

## What it is

- **Self-hosted, single-operator** — runs in a container alongside your
  reverse proxy; one passphrase gates private-key operations.
- **Encryption at rest** — every private key is wrapped with a per-cert DEK
  under a passphrase-derived KEK held only in memory. Locking the app
  zeroes the KEK.
- **Issue → rotate → revoke → deploy** as a closed loop. Rotation
  optionally re-deploys to configured paths (nginx, Caddy, haproxy, etc.)
  in the same transaction.
- **Public CRL endpoint** baked into the CRL Distribution Points extension
  of every cert at issuance.
- **Pure Go**, builds to a static binary in a `scratch` image.

## What it isn't (by design)

- Not an ACME server. Not an OCSP responder. Not a multi-tenant CA.
- No external CSR signing, no JSON/REST API in v1, no horizontal scaling.

## Documentation

The spec is split by concern. Each doc owns one area; cross-refs connect
them.

| Doc | Owns | Read it for |
| --- | --- | --- |
| [docs/SPEC.md](docs/SPEC.md) | Product surface | What homepki does, the stack, deployment shape, env vars, verification plan. Start here. |
| [docs/LIFECYCLE.md](docs/LIFECYCLE.md) | Cert/key/CRL behaviour | Locking, key encryption design (KEK→DEK→key), rotation, revocation, CRL regeneration policy. |
| [docs/STORAGE.md](docs/STORAGE.md) | Persistence | SQLite choice, full schema, migrations, transactions, backup, retention. |
| [docs/API.md](docs/API.md) | HTTP wire form | Routes, request/response shapes, content types, status codes, idempotency model. |
| [docs/COLD_ROOTS.md](docs/COLD_ROOTS.md) | **v2 design** | Cold-storage of root keys in a separate, removable database. v1 has the schema hooks ready; the rest is post-v1. |

## Mockups

[mockups/index.html](mockups/index.html) — the main view (CAs table + leaves
table) with live status filters. Open in a browser, no build step.

## Development environment

A devcontainer is included. Open in VS Code with the Dev Containers
extension and let it build; you'll get Go, Docker-in-Docker, and the
recommended extensions installed.

## License

TBD.
