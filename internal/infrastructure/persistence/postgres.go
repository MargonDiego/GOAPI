package persistence

import (
	"errors"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// newGormLogger crea un logger de GORM que usa zerolog como backend.
// Solo loguea errores y queries lentas (>200ms), no todas las consultas SQL.
func newGormLogger() gormlogger.Interface {
	return gormlogger.New(
		&zerologWriter{logger: log.Logger},
		gormlogger.Config{
			SlowThreshold:             200 * time.Millisecond, // Log queries > 200ms
			LogLevel:                  gormlogger.Warn,        // Solo warnings y errores
			IgnoreRecordNotFoundError: true,                   // ErrRecordNotFound no es error
			Colorful:                  false,                  // Sin colores ANSI en Docker
		},
	)
}

// zerologWriter adapta zerolog a la interfaz logger.Writer de GORM.
type zerologWriter struct {
	logger zerolog.Logger
}

func (w *zerologWriter) Printf(format string, args ...interface{}) {
	// GORM llama a Printf para todos los logs (SQL, errores, warnings).
	// Solo logueamos a nivel Warn porque el Config ya filtra por LogLevel.
	w.logger.Warn().Msgf(format, args...)
}

// connectDB es la funciÃ³n interna que abre la conexiÃ³n con configuraciÃ³n comÃºn.
func connectDB(dsn string, maxOpen, maxIdle int) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: newGormLogger(),
	})
	if err != nil {
		return nil, err
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(maxOpen)
	sqlDB.SetMaxIdleConns(maxIdle)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)

	return db, nil
}

func NewPostgresDB(dsn, migrationDSN string) (*gorm.DB, error) {
	if err := runMigrations(migrationDSN); err != nil {
		return nil, err
	}

	db, err := connectDB(dsn, 25, 10)
	if err != nil {
		return nil, err
	}

	seedDefaults(db)
	return db, nil
}

func ConnectPostgres(dsn string) (*gorm.DB, error) {
	return connectDB(dsn, 5, 2)
}

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
	adminRole := Role{Name: "Admin", IsSystem: true}
	db.FirstOrCreate(&adminRole, Role{Name: "Admin"})
	if !adminRole.IsSystem {
		db.Model(&adminRole).Update("is_system", true)
	}

	userRole := Role{Name: "User", IsSystem: true}
	db.FirstOrCreate(&userRole, Role{Name: "User"})
	if !userRole.IsSystem {
		db.Model(&userRole).Update("is_system", true)
	}

	readPerm := Permission{Name: "read:users"}
	db.FirstOrCreate(&readPerm, Permission{Name: "read:users"})

	writePerm := Permission{Name: "write:users"}
	db.FirstOrCreate(&writePerm, Permission{Name: "write:users"})

	manageRolesPerm := Permission{Name: "manage:roles"}
	db.FirstOrCreate(&manageRolesPerm, Permission{Name: "manage:roles"})

	manageUsersPerm := Permission{Name: "manage:users"}
	db.FirstOrCreate(&manageUsersPerm, Permission{Name: "manage:users"})

	readEstudiantesPerm := Permission{Name: "read:estudiantes"}
	db.FirstOrCreate(&readEstudiantesPerm, Permission{Name: "read:estudiantes"})

	manageEstudiantesPerm := Permission{Name: "manage:estudiantes"}
	db.FirstOrCreate(&manageEstudiantesPerm, Permission{Name: "manage:estudiantes"})

	readIncidenciasPerm := Permission{Name: "read:incidencias"}
	db.FirstOrCreate(&readIncidenciasPerm, Permission{Name: "read:incidencias"})

	manageIncidenciasPerm := Permission{Name: "manage:incidencias"}
	db.FirstOrCreate(&manageIncidenciasPerm, Permission{Name: "manage:incidencias"})

	resolveIncidenciasPerm := Permission{Name: "resolve:incidencias"}
	db.FirstOrCreate(&resolveIncidenciasPerm, Permission{Name: "resolve:incidencias"})

	db.Model(&adminRole).Association("Permissions").Append(&readPerm, &writePerm, &manageRolesPerm, &manageUsersPerm, &readEstudiantesPerm, &manageEstudiantesPerm, &readIncidenciasPerm, &manageIncidenciasPerm, &resolveIncidenciasPerm)
	db.Model(&userRole).Association("Permissions").Append(&readPerm, &readIncidenciasPerm)
}
