package store

import (
	"cmp"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"regexp"
	"slices"
	"strconv"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

var migrationName = regexp.MustCompile(`^(\d{4})_.+\.up\.sql$`)

// Migrate brings the schema up to the latest embedded version.
// Forward-only; see STORAGE.md §4.
func Migrate(db *sql.DB) error {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER  PRIMARY KEY,
			applied_at DATETIME NOT NULL
		)
	`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	pending, err := loadMigrations()
	if err != nil {
		return err
	}

	applied := map[int]bool{}
	rows, err := db.Query(`SELECT version FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("read schema_migrations: %w", err)
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return err
		}
		applied[v] = true
	}
	rows.Close()

	for _, m := range pending {
		if applied[m.version] {
			continue
		}
		body, err := migrationFS.ReadFile("migrations/" + m.name)
		if err != nil {
			return fmt.Errorf("read %s: %w", m.name, err)
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(body)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply %s: %w", m.name, err)
		}
		if _, err := tx.Exec(
			`INSERT INTO schema_migrations(version, applied_at) VALUES (?, datetime('now'))`,
			m.version,
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record %s: %w", m.name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit %s: %w", m.name, err)
		}
		slog.Info("migration applied", "version", m.version, "file", m.name)
	}
	return nil
}

type migration struct {
	version int
	name    string
}

func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("list migrations: %w", err)
	}
	out := make([]migration, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := migrationName.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, fmt.Errorf("migration %q does not match NNNN_*.up.sql", e.Name())
		}
		v, err := strconv.Atoi(m[1])
		if err != nil {
			return nil, fmt.Errorf("parse version of %q: %w", e.Name(), err)
		}
		out = append(out, migration{version: v, name: e.Name()})
	}
	slices.SortFunc(out, func(a, b migration) int { return cmp.Compare(a.version, b.version) })
	return out, nil
}
