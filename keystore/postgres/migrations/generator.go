package migrations

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/eventsalsa/encryption/keystore/postgres"
)

var validIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Config configures migration generation.
type Config struct {
	// OutputFolder is the directory where the migration file will be written.
	OutputFolder string

	// OutputFilename is the name of the migration file.
	OutputFilename string

	// Postgres controls schema and table overrides using postgres.Config.
	Postgres postgres.Config
}

// DefaultConfig returns the default migration generator configuration.
func DefaultConfig() Config {
	return Config{
		OutputFolder:   "migrations",
		OutputFilename: timestampedFilename(),
		Postgres:       postgres.DefaultConfig(),
	}
}

// SQL returns the PostgreSQL keystore migration SQL for the given config.
func SQL(cfg postgres.Config) (string, error) {
	cfg = postgres.ApplyDefaults(cfg)
	if err := validateConfig(cfg); err != nil {
		return "", err
	}

	data, err := FS.ReadFile("001_encryption_keys.sql")
	if err != nil {
		return "", fmt.Errorf("read embedded migration: %w", err)
	}

	defaults := postgres.DefaultConfig()
	sql := string(data)
	sql = strings.ReplaceAll(sql, defaults.Schema+"."+defaults.Table, cfg.Schema+"."+cfg.Table)
	sql = strings.ReplaceAll(sql, "idx_"+defaults.Table+"_", "idx_"+cfg.Table+"_")

	return sql, nil
}

// GeneratePostgres writes the PostgreSQL keystore migration file.
func GeneratePostgres(config *Config) error {
	if config == nil {
		return fmt.Errorf("config is required")
	}

	if config.OutputFolder == "" {
		config.OutputFolder = "migrations"
	}
	if config.OutputFilename == "" {
		config.OutputFilename = timestampedFilename()
	}

	sql, err := SQL(config.Postgres)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(config.OutputFolder, 0o750); err != nil {
		return fmt.Errorf("create output folder: %w", err)
	}

	outputPath := filepath.Join(config.OutputFolder, config.OutputFilename)
	if err := os.WriteFile(outputPath, []byte(sql), 0o600); err != nil {
		return fmt.Errorf("write migration file: %w", err)
	}

	return nil
}

func timestampedFilename() string {
	return fmt.Sprintf("%s_init_encryption_keys.sql", time.Now().Format("20060102150405"))
}

func validateConfig(cfg postgres.Config) error {
	if !validIdentifier.MatchString(cfg.Schema) {
		return fmt.Errorf("invalid schema %q: must be a PostgreSQL identifier", cfg.Schema)
	}
	if !validIdentifier.MatchString(cfg.Table) {
		return fmt.Errorf("invalid table %q: must be a PostgreSQL identifier", cfg.Table)
	}
	return nil
}
