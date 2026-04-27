// @title           Clean Architecture Go API
// @version         1.0
// @description     API REST con autenticación JWT y control de permisos basado en roles.
// @host            localhost:8080
// @BasePath        /api
// @securityDefinitions.apikey BearerAuth
// @in              header
// @name            Authorization
// @description     Ingresá el token con el prefijo Bearer. Ejemplo: "Bearer {token}"
package main

import (
	"net/http"
	"os"
	"time"

	_ "github.com/diego/go-api/docs"
	"github.com/diego/go-api/internal/application"
	"github.com/diego/go-api/internal/infrastructure/crypto"
	"github.com/diego/go-api/internal/infrastructure/database"
	mypresentation "github.com/diego/go-api/internal/presentation/http"
	"github.com/diego/go-api/internal/presentation/http/handlers"
	"github.com/diego/go-api/internal/presentation/http/middleware"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	// Configuración del logger global.
	// En desarrollo: output legible con colores.
	// En producción: JSON puro, listo para Loki/Grafana.
	if getEnv("APP_ENV", "development") == "production" {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Logger = log.Output(zerolog.NewConsoleWriter())
	}
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs

	// Carga variables de entorno desde .env (solo en desarrollo)
	if err := godotenv.Load(); err != nil {
		log.Debug().Msg("No .env file found, using system environment variables")
	}

	// Entorno y Configuración
	jwtSecret := []byte(getEnv("JWT_SECRET", ""))
	port := getEnv("PORT", "8080")
	dsn := getEnv("DB_DSN", "")
	migrationDSN := getEnv("MIGRATION_DSN", "")
	emailKey := []byte(getEnv("EMAIL_ENCRYPTION_KEY", ""))

	if dsn == "" {
		log.Fatal().Msg("DB_DSN environment variable is required")
	}
	if migrationDSN == "" {
		log.Fatal().Msg("MIGRATION_DSN environment variable is required")
	}
	if len(jwtSecret) == 0 {
		log.Fatal().Msg("JWT_SECRET environment variable is required")
	}
	if len(emailKey) != 32 {
		log.Fatal().Msg("EMAIL_ENCRYPTION_KEY must be exactly 32 bytes (AES-256)")
	}

	// 1. Capa de Infraestructura (Base de datos PostgreSQL)
	db, err := database.NewPostgresDB(dsn, migrationDSN)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to PostgreSQL database")
	}
	userRepo := database.NewUserRepository(db)
	roleRepo := database.NewRoleRepository(db)

	// Encryptor para PII (fail-fast garantizado por la validación de emailKey arriba).
	enc, _ := crypto.NewEncryptor(emailKey)

	// 2. Capa de Aplicación (Servicios de dominio)
	authService := application.NewAuthService(userRepo, jwtSecret, enc)
	userService := application.NewUserService(userRepo, roleRepo)
	roleService := application.NewRoleService(roleRepo)

	// 3. Capa de Presentación HTTP (Middlewares y Controladores)
	authHandler := handlers.NewAuthHandler(authService)
	userHandler := handlers.NewUserHandler(userService)
	roleHandler := handlers.NewRoleHandler(roleService)
	authMw := middleware.NewAuthMiddleware(jwtSecret)

	// Inicialización de Router con logging de requests
	router := mypresentation.NewRouter(authHandler, userHandler, roleHandler, authMw)
	router.Use(middleware.RequestLogger())

	log.Info().Str("port", port).Msg("Starting API server")
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      router,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal().Err(err).Msg("Server stopped abruptly")
	}
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
