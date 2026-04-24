package database

import (
	"errors"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func NewPostgresDB(dsn, migrationDSN string) (*gorm.DB, error) {
	// 1. Ejecutar migraciones con el usuario privilegiado (DDL).
	if err := runMigrations(migrationDSN); err != nil {
		return nil, err
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	// 2. Configura el pool de conexiones para evitar saturar Postgres bajo carga.
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)

	seedDefaults(db)

	return db, nil
}

// runMigrations aplica todas las migraciones pendientes desde el directorio /migrations.
// ErrNoChange no es un error — significa que el schema ya está al día.
func runMigrations(dsn string) error {
	m, err := migrate.New("file://migrations", dsn)
	if err != nil {
		return err
	}
	defer m.Close()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}
	return nil
}

func seedDefaults(db *gorm.DB) {
	adminRole := Role{Name: "Admin"}
	db.FirstOrCreate(&adminRole, Role{Name: "Admin"})

	userRole := Role{Name: "User"}
	db.FirstOrCreate(&userRole, Role{Name: "User"})

	readPerm := Permission{Name: "read:users"}
	db.FirstOrCreate(&readPerm, Permission{Name: "read:users"})

	writePerm := Permission{Name: "write:users"}
	db.FirstOrCreate(&writePerm, Permission{Name: "write:users"})

	db.Model(&adminRole).Association("Permissions").Append(&readPerm, &writePerm)
	db.Model(&userRole).Association("Permissions").Append(&readPerm)
}
