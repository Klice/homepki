# homepki — Cold roots (v2 design)

> **Status: v2 design.** Not implemented in v1. Linked from STORAGE.md and
> LIFECYCLE.md only at the points where v1 has forward-compat hooks.
> Everything else about this feature lives here.

> Companion docs (v1):
> [SPEC.md](SPEC.md), [LIFECYCLE.md](LIFECYCLE.md),
> [STORAGE.md](STORAGE.md), [API.md](API.md).

---

## 1. Motivation

In v1 every private key — root, intermediate, leaf — is encrypted under the
same KEK held in process memory while the app is unlocked. A host
compromise that captures process memory while unlocked therefore exposes
**every** private key, including the roots.

Roots are the highest-value secret in the PKI: an attacker holding a root
key can issue a new intermediate of their choosing and from there issue
arbitrary trusted leaf certs across the whole trust domain. Roots are also
the **least** used keys: they sign only when issuing or rotating an
intermediate, or when regenerating the root's CRL after revoking an
intermediate. Both are weeks-or-months events.

Asymmetry between value and usage frequency is exactly the case for cold
storage. v2 splits root-key material into a separate, removable database
encrypted under a separate KEK, so the host's daily attack surface no
longer includes the root keys.

Intermediate and leaf keys stay hot — every leaf issuance signs with the
intermediate, so cold-storing intermediates would defeat the point.

---

## 2. Two-tier KEK model

| Tier   | Used to sign                                          | KEK source                          | Key material lives in |
| ------ | ----------------------------------------------------- | ----------------------------------- | --------------------- |
| `main` | leaf certs, intermediate CRLs                         | `KEK_main` (passphrase A → Argon2id) | `homepki.db`         |
| `root` | intermediate certs, root CRLs                         | `KEK_root` (passphrase B → Argon2id) | `roots.db`           |

The two KEKs are independent. They derive from independent passphrases
with independent salts.

Each `cert_keys` row's `kek_tier` column ([STORAGE.md §5.4](STORAGE.md#54-cert_keys))
selects which KEK wrapped the DEK on that row.

---

## 3. File layout

### 3.1 New file: `roots.db`

A separate SQLite database that holds **only** root-tier key material. Its
schema is a strict subset of `homepki.db`'s schema:

| table                | scope in `roots.db`                              |
| -------------------- | ------------------------------------------------ |
| `schema_migrations`  | full table; tracks roots-db migration history    |
| `settings`           | own keys: `passphrase_verifier`, `kdf_salt`, `kdf_params`, optionally `created_at` |
| `cert_keys`          | only rows where `kek_tier = 'root'`              |

`certificates`, `crls`, `deploy_targets`, `idempotency_tokens` stay
exclusively in `homepki.db`. Root cert metadata (DER, status, fingerprint)
is in `homepki.db`'s `certificates` table; only the encrypted private-key
bytes move.

### 3.2 Filesystem placement

`roots.db` is **not** placed under `CM_DATA_DIR`. The intended pattern is:

- `CM_DATA_DIR=/data` — bound to a persistent host volume, always mounted.
- `CM_ROOTS_DB=/secrets/roots.db` — a separate path, typically on
  removable media or a tmpfs that the operator mounts only when needed.
  When the operator unmounts the parent directory, the file becomes
  inaccessible to the running container.

The app on startup checks for the file's presence and surfaces "root
operations available / not available" in the UI. It does **not** open the
file at startup; it opens it on demand for a root operation, after the
operator supplies the root passphrase.

### 3.3 Operating modes

| Mode                              | `homepki.db` | `roots.db`     | What works                                     |
| --------------------------------- | ------------ | -------------- | ---------------------------------------------- |
| Daily                             | mounted      | not mounted    | leaf and intermediate ops; cached root CRLs    |
| Maintenance                       | mounted      | mounted        | everything, plus root ops (after root unlock)  |
| Setup (first run, v2 installs)    | mounted      | created here   | initial root issuance                          |

There is no "roots.db only" mode.

---

## 4. Cryptographic notes

`KEK_root` is derived identically to `KEK_main` — Argon2id (time=3,
memory=64MiB, threads=2, key_len=32) — but with an independent 16-byte
salt stored in `roots.db`'s `settings` table. The verifier construction is
identical: `HMAC-SHA256(KEK_root, "homepki/verify/v1")`, stored alongside
the salt.

The AAD bound to root-tier ciphertexts is the same as for main-tier:
`"homepki/dek/v1|" || cert_id` for the DEK wrap and
`"homepki/key/v1|" || cert_id` for the key encryption (LIFECYCLE.md §2.2).
A move between tiers therefore requires re-wrapping (re-encrypting) the
DEK under the other KEK; the inner key ciphertext does not need to change.

`KEK_root` is **never held across requests.** It's derived per-operation
from the prompt that accompanies the root form, used to unwrap the
relevant DEK, then zeroed. This keeps `KEK_root` out of memory at all
times except during the few hundred milliseconds of an active root
operation.

---

## 5. Operations affected

### 5.1 Gated on `roots.db` mounted **and** root passphrase supplied

- Issue an intermediate (signs with root key).
- Rotate an intermediate (issue successor; old intermediate's status is
  updated in `homepki.db` without touching `roots.db`, but the new
  intermediate's cert is signed by the root).
- Revoke an intermediate (updates root's CRL, which the root key signs).
- Rotate a root (writes a new root row whose key material lands in
  `roots.db` under a new id; the old root stays for audit).
- Download root `key.pem` (decrypts root key for export — rarely needed).
- Regenerate the root's CRL (e.g. after revocation, or because
  `next_update` has passed).

### 5.2 Available without `roots.db`

- All leaf operations (issue, rotate, revoke, deploy, downloads).
- All operations on existing intermediates that don't require the root
  key (regen the *intermediate's* CRL, issue/revoke leaves, etc.).
- Browse root metadata (subject, fingerprint, expiry, chain).
- Download root `cert.pem`, `chain.pem` (public material lives in
  `homepki.db`).
- Serve the root's CRL **as the cached DER** (same fall-back pattern as
  the existing locked-state behaviour for intermediates,
  [LIFECYCLE.md §6.5](LIFECYCLE.md#65-the-public-endpoint-and-the-lock-state)).
  When `next_update` has passed and `roots.db` is unmounted, the endpoint
  serves the stale DER with the `Warning: 110` header. The window of
  staleness is bounded by how often the operator mounts roots.db; a root's
  CRL rarely needs to be fresher than weeks anyway.

### 5.3 New endpoint behaviour

For each op in §5.1, the form rendered by the corresponding GET grows two
fields:

- `root_passphrase` (required, password input)
- `root_passphrase_token` (form-token equivalent for the root operation)

The POST handler:

1. Validates CSRF and the standard form_token.
2. Checks `roots.db` is mounted; if not → **412 Precondition Failed** with a
   page explaining how to mount.
3. Derives `KEK_root` from the supplied passphrase and the salt in
   `roots.db`. Wrong passphrase → **400** with rate-limit/backoff identical
   to main-tier unlock.
4. Looks up the relevant root's `cert_keys` row in `roots.db` by `cert_id`.
5. Performs the op (sign, regen CRL, etc.).
6. Zeros `KEK_root`.

The root passphrase is **not** stored in any session, cookie, or in-memory
slot beyond the request handler.

---

## 6. UX flow

### 6.1 Daily

Operator unlocks with passphrase A. The "issue intermediate" / "issue
root" / "rotate intermediate" / "revoke intermediate" buttons render but
are disabled with hovertext: *"roots.db not mounted — see Maintenance
guide."* Everything else works as v1.

### 6.2 Maintenance (issuing/rotating an intermediate)

1. Operator mounts the roots.db volume (USB, encrypted file, tmpfs that
   they `cp` into, however they want).
2. Operator clicks **issue intermediate**. The form now also asks for
   passphrase B.
3. Operator submits. Cert is signed; UI shows success.
4. Operator unmounts roots.db. The container's view of `/secrets/roots.db`
   becomes a missing-file error; subsequent root ops are gated again.

### 6.3 First run on v2

- v2 setup form prompts for **two** passphrases: main and root, both ≥ 12
  chars, must differ from each other.
- App writes `homepki.db` (with `KEK_main`-derived verifier) and `roots.db`
  (with `KEK_root`-derived verifier).
- After the operator issues their first root, the root's `cert_keys` row
  goes into `roots.db`.
- App immediately surfaces a "back up roots.db **and** record both
  passphrases" reminder, refusing to dismiss until the operator
  acknowledges.

### 6.4 Loss of root passphrase

Catastrophic — the root key is unrecoverable. Effects:
- Existing certs continue working until they expire. Existing CRLs continue
  serving from `homepki.db`'s cache.
- Cannot issue new intermediates ⇒ cannot keep extending the trust chain.
- Cannot revoke intermediates via CRL (would require signing the root's
  CRL).
- Recovery path: rotate the root by issuing a brand-new root + intermediate
  pair, redistribute the new root cert out-of-band, re-issue all leaves
  under the new chain. (i.e. rebuild the PKI.) Document this in the
  operator guide.

---

## 7. Migration from v1 to v2

A v1 install has all rows in `cert_keys` with `kek_tier = 'main'`. v2
introduces `roots.db` and migrates root-tier rows over.

Migration steps, in order, all behind a single guarded admin action
("migrate to two-tier"):

1. Operator supplies main passphrase (already unlocked) and **chooses a new
   root passphrase**.
2. App creates `roots.db` at the configured path, runs its initial
   migration (creates `schema_migrations`, `settings`, `cert_keys`),
   writes the root verifier and salt.
3. For each row in main's `cert_keys` whose corresponding cert has
   `type = 'root_ca'`:
   - Decrypt the DEK using `KEK_main`.
   - Re-wrap the DEK using `KEK_root` (fresh nonce).
   - Write the row to `roots.db`'s `cert_keys` with `kek_tier = 'root'`,
     same `cert_id`, same inner ciphertext (no need to re-encrypt the
     PKCS#8 DER under a new DEK).
   - Verify by re-decrypting the round-tripped DEK and checking that the
     resulting key matches `der_cert`'s public key.
   - Delete the row from main's `cert_keys`.
4. Atomic-ish: the migration runs row-by-row, and partially-migrated
   state is recoverable — a row in `homepki.db.cert_keys` and not in
   `roots.db.cert_keys` means the migration was interrupted; rerun is
   idempotent (skip rows already moved).
5. Migration is non-destructive of the *cert metadata* and the *inner
   ciphertext* — only the wrapper changes. If anything goes wrong, the
   operator can roll back by re-wrapping under `KEK_main` and writing
   back to main.

After migration, root operations require the new passphrase + the file.

---

## 8. CRL freshness considerations

The root's CRL is signed by the root key. Without `roots.db` mounted, we
serve the stale cached DER (per §5.2). Pragmatic implications:

- A root CRL rarely needs to be fresher than weeks. Intermediates are
  rarely revoked. The stale window in practice is "however long since the
  operator last did maintenance".
- If an emergency revocation of an intermediate is required, the operator
  must mount `roots.db` and unlock to publish the fresh CRL. This is by
  design — the operation is rare and warrants the ceremony.
- For a really catastrophic case (intermediate key compromise, immediate
  revocation needed), the operator may also choose to publish the fresh
  CRL out-of-band (sign offline, copy the DER into `crls` table via a
  recovery tool). v2 does not need to implement this; it's a manual
  procedure documented in the operator guide.

---

## 9. Backup

Two files now matter:

- `homepki.db` — backed up regularly, contains all metadata + intermediate
  and leaf keys.
- `roots.db` — backed up at-rest on the same removable medium (or a
  separate one). **Both** must be restored to fully recover.

Backup of `homepki.db` alone leaves you with cert records whose root keys
exist nowhere (until you restore `roots.db`). Existing chains keep
working; you just can't issue new intermediates.

The backup process per [STORAGE.md §8](STORAGE.md#8-backup-and-restore)
extends naturally — `VACUUM INTO` the same way for both files.

---

## 10. FK behaviour across files

SQLite's `FOREIGN KEY` enforcement does not span `ATTACH`-ed databases.
The `cert_keys.cert_id` FK to `certificates.id` therefore cannot be
enforced for rows that live in `roots.db`.

Mitigation:
- Application-level integrity check at startup when both files are mounted:
  every row in `roots.db.cert_keys` must have a matching `certificates`
  row in `homepki.db`. Mismatch → log a loud warning, proceed.
- Hard-deletion of cert rows is out of scope in v1 anyway; if v2 ever
  enables it, the delete handler must explicitly clean up the matching
  `roots.db.cert_keys` row before deleting from `certificates`.

---

## 11. Open decisions for v2

1. **Default path for `roots.db`** — proposed `/secrets/roots.db`, configurable
   via `CM_ROOTS_DB`. The conventions for "not mounted" detection (does
   the file not exist, or does the directory not exist?) need to be
   chosen.
2. **What if both passphrases are the same?** Reject at setup, force them
   to differ. Or allow it with a warning. Proposed: reject — the operator
   is opting into separation, identical passphrases nullifies that.
3. **Per-op vs per-session root unlock.** Spec assumes per-op (passphrase
   prompt on every root form). An alternative is a short-lived
   "root session" of, say, 5 minutes. Proposed: per-op for v2; revisit
   if the UX is too friction-heavy.
4. **Audit log of root operations.** v1 has no dedicated audit log. v2
   should probably add one (`audit_events` table?) since root ops are
   the events most likely to be subpoenaed or post-incident-reviewed.
   Out of scope for the schema-extension hooks in v1.
5. **Handling a missing `roots.db` during routine startup.** Proposed:
   start fine, surface "root ops unavailable" in UI, do not block any
   non-root path. Confirm.
