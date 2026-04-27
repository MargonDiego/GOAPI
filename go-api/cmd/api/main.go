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
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/diego/go-api/docs"
	"github.com/diego/go-api/internal/application"
	"github.com/diego/go-api/internal/config"
	"github.com/diego/go-api/internal/infrastructure/crypto"
	"github.com/diego/go-api/internal/infrastructure/database"
	mypresentation "github.com/diego/go-api/internal/presentation/http"
	"github.com/diego/go-api/internal/presentation/http/handlers"
	"github.com/diego/go-api/internal/presentation/http/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	// 1. Cargar Configuración (Fail-Fast: explota si falta algo)
	cfg, err := config.Load()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load configuration")
	}

	// 2. Configuración del logger global.
	if cfg.AppEnv == "production" {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Logger = log.Output(zerolog.NewConsoleWriter())
	}
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs

	// 3. Capa de Infraestructura (Base de datos PostgreSQL)
	db, err := database.NewPostgresDB(cfg.DBDsn, cfg.MigrationDsn)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to PostgreSQL database")
	}
	userRepo := database.NewUserRepository(db)
	roleRepo := database.NewRoleRepository(db)
	
	// Obtenemos la instancia nativa sql.DB para el healthcheck y para el cierre limpio
	sqlDB, err := db.DB()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get underlying sql.DB")
	}

	// Encryptor para PII
	enc, _ := crypto.NewEncryptor(cfg.EmailEncryptionKey)

	// 4. Capa de Aplicación (Servicios de dominio)
	authService := application.NewAuthService(userRepo, cfg.JWTSecret, enc)
	userService := application.NewUserService(userRepo, roleRepo, enc)
	roleService := application.NewRoleService(roleRepo)

	// 5. Capa de Presentación HTTP (Middlewares y Controladores)
	authHandler := handlers.NewAuthHandler(authService)
	userHandler := handlers.NewUserHandler(userService)
	roleHandler := handlers.NewRoleHandler(roleService)
	healthHandler := handlers.NewHealthHandler(sqlDB)
	authMw := middleware.NewAuthMiddleware(cfg.JWTSecret)

	// Inicialización de Router con logging de requests
	router := mypresentation.NewRouter(authHandler, userHandler, roleHandler, healthHandler, authMw)
	router.Use(middleware.RequestLogger())

	log.Info().Str("port", cfg.Port).Msg("Starting API server")
	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      router,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// 4. Iniciar el servidor en una goroutine
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal().Err(err).Msg("Server stopped abruptly")
		}
	}()

	// 5. Graceful Shutdown (Apagado elegante)
	quit := make(chan os.Signal, 1)
	// Escuchar SIGINT (Ctrl+C) y SIGTERM (Terminación de Kubernetes/Docker)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	
	<-quit // Bloquea hasta recibir la señal
	log.Info().Msg("Shutting down server gracefully...")

	// Damos 10 segundos para que las peticiones en curso terminen
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("Server forced to shutdown")
	}

	// Cerramos la conexión a la base de datos limpiamente
	log.Info().Msg("Closing database connection...")
	if err := sqlDB.Close(); err != nil {
		log.Error().Err(err).Msg("Error closing database")
	}

	log.Info().Msg("Server exited properly")
}
