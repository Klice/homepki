package store

import "github.com/google/uuid"

// NewCertID returns a fresh UUIDv4 in the canonical hyphenated form,
// suitable for use as a certificates.id (and matching the schema's
// "TEXT (UUID)" expectation in STORAGE.md §5.3).
func NewCertID() string {
	return uuid.NewString()
}
