CREATE TABLE settings (
    key        TEXT     PRIMARY KEY,
    value      BLOB,
    updated_at DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE certificates (
    id                  TEXT     PRIMARY KEY,
    type                TEXT     NOT NULL CHECK (type IN ('root_ca','intermediate_ca','leaf')),
    parent_id           TEXT     REFERENCES certificates(id),
    serial_number       TEXT     NOT NULL,
    subject_cn          TEXT     NOT NULL,
    subject_o           TEXT,
    subject_ou          TEXT,
    subject_l           TEXT,
    subject_st          TEXT,
    subject_c           TEXT,
    san_dns             TEXT     NOT NULL DEFAULT '[]',
    san_ip              TEXT     NOT NULL DEFAULT '[]',
    is_ca               INTEGER  NOT NULL,
    path_len_constraint INTEGER,
    key_algo            TEXT     NOT NULL CHECK (key_algo IN ('rsa','ecdsa','ed25519')),
    key_algo_params     TEXT,
    key_usage           TEXT     NOT NULL DEFAULT '[]',
    ext_key_usage       TEXT     NOT NULL DEFAULT '[]',
    not_before          DATETIME NOT NULL,
    not_after           DATETIME NOT NULL,
    der_cert            BLOB     NOT NULL,
    fingerprint_sha256  TEXT     NOT NULL,
    status              TEXT     NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked','superseded')),
    revoked_at          DATETIME,
    revocation_reason   INTEGER,
    replaces_id         TEXT     REFERENCES certificates(id),
    replaced_by_id      TEXT     REFERENCES certificates(id),
    created_at          DATETIME NOT NULL DEFAULT (datetime('now')),
    UNIQUE (parent_id, serial_number)
);

CREATE INDEX idx_certificates_parent_status ON certificates(parent_id, status);
CREATE INDEX idx_certificates_not_after     ON certificates(not_after);
CREATE INDEX idx_certificates_fingerprint   ON certificates(fingerprint_sha256);

CREATE TABLE cert_keys (
    cert_id      TEXT     PRIMARY KEY REFERENCES certificates(id) ON DELETE CASCADE,
    kek_tier     TEXT     NOT NULL DEFAULT 'main' CHECK (kek_tier IN ('main','root')),
    wrapped_dek  BLOB     NOT NULL,
    dek_nonce    BLOB     NOT NULL,
    cipher_nonce BLOB     NOT NULL,
    ciphertext   BLOB     NOT NULL,
    created_at   DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE crls (
    issuer_cert_id TEXT     NOT NULL REFERENCES certificates(id),
    crl_number     INTEGER  NOT NULL,
    this_update    DATETIME NOT NULL,
    next_update    DATETIME NOT NULL,
    der            BLOB     NOT NULL,
    updated_at     DATETIME NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (issuer_cert_id, crl_number)
);

CREATE INDEX idx_crls_issuer_latest ON crls(issuer_cert_id, crl_number DESC);

CREATE TABLE deploy_targets (
    id                   TEXT     PRIMARY KEY,
    cert_id              TEXT     NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
    name                 TEXT     NOT NULL,
    cert_path            TEXT     NOT NULL,
    key_path             TEXT     NOT NULL,
    chain_path           TEXT,
    mode                 TEXT     NOT NULL,
    owner                TEXT,
    "group"              TEXT,
    post_command         TEXT,
    auto_on_rotate       INTEGER  NOT NULL DEFAULT 0,
    last_deployed_at     DATETIME,
    last_deployed_serial TEXT,
    last_status          TEXT     CHECK (last_status IN ('ok','failed')),
    last_error           TEXT,
    created_at           DATETIME NOT NULL DEFAULT (datetime('now')),
    UNIQUE (cert_id, name)
);

CREATE INDEX idx_deploy_targets_cert_id ON deploy_targets(cert_id);

CREATE TABLE idempotency_tokens (
    token      TEXT     PRIMARY KEY,
    created_at DATETIME NOT NULL,
    used_at    DATETIME,
    result_url TEXT,
    expires_at DATETIME NOT NULL
);

CREATE INDEX idx_idempotency_expires_at ON idempotency_tokens(expires_at);
