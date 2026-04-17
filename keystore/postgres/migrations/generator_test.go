package migrations

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eventsalsa/encryption/keystore/postgres"
)

func TestSQLDefaultConfigMatchesEmbeddedMigration(t *testing.T) {
	t.Parallel()

	want, err := FS.ReadFile("001_encryption_keys.sql")
	if err != nil {
		t.Fatalf("read embedded migration: %v", err)
	}

	got, err := SQL(postgres.Config{})
	if err != nil {
		t.Fatalf("build migration SQL: %v", err)
	}

	if got != string(want) {
		t.Fatalf("expected generated SQL to match embedded migration")
	}
}

func TestSQLAppliesSchemaAndTableOverrides(t *testing.T) {
	t.Parallel()

	got, err := SQL(postgres.Config{
		Schema: "custom_schema",
		Table:  "custom_keys",
	})
	if err != nil {
		t.Fatalf("build migration SQL: %v", err)
	}

	if !strings.Contains(got, "CREATE TABLE IF NOT EXISTS custom_schema.custom_keys") {
		t.Fatalf("expected custom schema and table in CREATE TABLE statement")
	}
	if !strings.Contains(got, "ON custom_schema.custom_keys(scope, scope_id, revoked_at)") {
		t.Fatalf("expected custom schema and table in index statement")
	}
	if !strings.Contains(got, "CREATE INDEX IF NOT EXISTS idx_custom_keys_active") {
		t.Fatalf("expected index names to follow custom table name")
	}
	if strings.Contains(got, "infrastructure.encryption_keys") {
		t.Fatalf("did not expect default schema/table in custom migration")
	}
}

func TestSQLRejectsInvalidIdentifiers(t *testing.T) {
	t.Parallel()

	_, err := SQL(postgres.Config{
		Schema: "custom-schema",
		Table:  "custom_keys",
	})
	if err == nil {
		t.Fatalf("expected invalid identifier error")
	}
}

func TestGeneratePostgresWritesFile(t *testing.T) {
	t.Parallel()

	config := DefaultConfig()
	config.OutputFolder = t.TempDir()
	config.OutputFilename = "custom.sql"
	config.Postgres = postgres.Config{
		Schema: "custom_schema",
		Table:  "custom_keys",
	}

	if err := GeneratePostgres(&config); err != nil {
		t.Fatalf("generate migration: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(config.OutputFolder, config.OutputFilename))
	if err != nil {
		t.Fatalf("read generated file: %v", err)
	}

	want, err := SQL(config.Postgres)
	if err != nil {
		t.Fatalf("build expected migration: %v", err)
	}

	if string(got) != want {
		t.Fatalf("generated file did not match expected migration")
	}
}
