// Command migrate-gen generates SQL migration files for the PostgreSQL keystore.
//
// Usage:
//
//	go run github.com/eventsalsa/encryption/cmd/migrate-gen -output migrations
//
// Or print the SQL directly:
//
//	go run github.com/eventsalsa/encryption/cmd/migrate-gen -stdout
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/eventsalsa/encryption/keystore/postgres"
	"github.com/eventsalsa/encryption/keystore/postgres/migrations"
)

func main() {
	var (
		outputFolder   = flag.String("output", "migrations", "Output folder for migration file")
		outputFilename = flag.String("filename", "", "Output filename (default: timestamp-based)")
		schema         = flag.String("schema", postgres.DefaultSchema, "Schema name for encryption keys")
		table          = flag.String("table", postgres.DefaultTable, "Table name for encryption keys")
		stdout         = flag.Bool("stdout", false, "Print the migration to stdout instead of writing a file")
	)

	flag.Parse()

	config := migrations.DefaultConfig()
	config.OutputFolder = *outputFolder
	config.Postgres.Schema = *schema
	config.Postgres.Table = *table

	if *outputFilename != "" {
		config.OutputFilename = *outputFilename
	}

	if *stdout {
		sql, err := migrations.SQL(config.Postgres)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating migration: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(sql)
		return
	}

	if err := migrations.GeneratePostgres(&config); err != nil {
		fmt.Fprintf(os.Stderr, "Error generating migration: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Generated PostgreSQL migration: %s\n", filepath.Join(config.OutputFolder, config.OutputFilename))
}
