package config

import (
	"errors"
	"fmt"
	"os"

	"github.com/joho/godotenv"
	"github.com/rs/zerolog/log"
)

// Config centraliza todas las variables de entorno fuertemente tipadas.
type Config struct {
	AppEnv             string
	Port               string
	DBDsn              string
	MigrationDsn       string
	JWTSecret          []byte
	EmailEncryptionKey []byte
}

// Load lee, valida y retorna la configuración de la aplicación.
// Si falta una variable requerida, devuelve un error para hacer "Fail Fast".
func Load() (*Config, error) {
	// Intentamos cargar .env para desarrollo local
	if err := godotenv.Load(); err != nil {
		log.Debug().Msg("No .env file found, reading straight from environment variables")
	}

	cfg := &Config{
		AppEnv: getEnv("APP_ENV", "development"),
		Port:   getEnv("PORT", "8080"),
	}

	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		return nil, errors.New("DB_DSN environment variable is required")
	}
	cfg.DBDsn = dsn

	mDsn := os.Getenv("MIGRATION_DSN")
	if mDsn == "" {
		return nil, errors.New("MIGRATION_DSN environment variable is required")
	}
	cfg.MigrationDsn = mDsn

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		return nil, errors.New("JWT_SECRET environment variable is required")
	}
	cfg.JWTSecret = []byte(jwtSecret)

	emailKey := os.Getenv("EMAIL_ENCRYPTION_KEY")
	if len(emailKey) != 32 {
		return nil, fmt.Errorf("EMAIL_ENCRYPTION_KEY must be exactly 32 bytes (AES-256), got %d", len(emailKey))
	}
	cfg.EmailEncryptionKey = []byte(emailKey)

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
