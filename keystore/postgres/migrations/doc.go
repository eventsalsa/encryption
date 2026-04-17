// Package migrations exposes the embedded PostgreSQL keystore migration.
//
// For the quick CLI path, use:
//
//	go run github.com/eventsalsa/encryption/cmd/migrate-gen -output migrations
//
// To print the SQL instead of writing a file:
//
//	go run github.com/eventsalsa/encryption/cmd/migrate-gen -stdout
//
// For advanced usage, call [SQL] or [GeneratePostgres] directly.
package migrations
