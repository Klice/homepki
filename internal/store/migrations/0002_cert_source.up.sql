-- Track whether a cert was minted by homepki or imported from an external
-- PKI. Used by the UI to surface an "imported" badge and by the cert-import
-- handler to identify pre-existing rows.
--
-- Backfill: existing rows pre-import are all homepki-issued (the import
-- flow didn't exist), so the column defaults to 'issued'.

ALTER TABLE certificates ADD COLUMN source TEXT NOT NULL DEFAULT 'issued'
    CHECK (source IN ('issued', 'imported'));
