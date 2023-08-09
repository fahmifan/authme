package psql

import (
	"database/sql"
	"embed"

	migrate "github.com/rubenv/sql-migrate"
)

//go:embed migrations
var schemaFS embed.FS

func MigrateUp(db *sql.DB) error {
	mgr := migrate.EmbedFileSystemMigrationSource{
		FileSystem: schemaFS,
		Root:       "migrations",
	}

	_, err := migrate.Exec(db, "postgres", mgr, migrate.Up)
	return err
}

func MigrateDown(db *sql.DB) error {
	mgr := migrate.EmbedFileSystemMigrationSource{
		FileSystem: schemaFS,
		Root:       "migrations",
	}

	_, err := migrate.Exec(db, "postgres", mgr, migrate.Down)
	return err
}
