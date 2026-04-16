package migrations

import "embed"

// FS embeds the SQL migration files for the postgres key store.
//
//go:embed *.sql
var FS embed.FS
