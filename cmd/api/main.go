// @title           Clean Architecture Go API
// @version         1.0
// @description     API REST con autenticaciÃ³n JWT y control de permisos basado en roles.
// @host            localhost:8080
// @BasePath        /api/v1
// @securityDefinitions.apikey BearerAuth
// @in              header
// @name            Authorization
// @description     IngresÃ¡ el token con el prefijo Bearer. Ejemplo: "Bearer {token}"
package main

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/MargonDiego/GOAPI/docs"
	"github.com/MargonDiego/GOAPI/internal/application"
	"github.com/MargonDiego/GOAPI/internal/config"
	"github.com/MargonDiego/GOAPI/internal/domain"
	"github.com/MargonDiego/GOAPI/internal/infrastructure/cache"
	"github.com/MargonDiego/GOAPI/internal/infrastructure/crypto"
	"github.com/MargonDiego/GOAPI/internal/infrastructure/persistence"
	"github.com/MargonDiego/GOAPI/internal/infrastructure/storage"
	"github.com/MargonDiego/GOAPI/internal/presentation/rest"
	"github.com/MargonDiego/GOAPI/internal/presentation/rest/handlers"
	"github.com/MargonDiego/GOAPI/internal/presentation/rest/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

// --- Tipos auxiliares para el wiring ---

type infraDeps struct {
	db              *gorm.DB
	sqlDB           *sql.DB
	userRepo        domain.UserRepository
	roleRepo        domain.RoleRepository
	auditRepo       domain.AuditRepository
	estudianteRepo  domain.EstudianteRepository
	incidenciaRepo  domain.IncidenciaRepository
	fileStorage     domain.FileStorage
	enc             *crypto.Encryptor
	versionCache    *cache.TokenVersionCache
}

type appServices struct {
	auth       application.AuthService
	user       application.UserService
	role       application.RoleService
	estudiante application.EstudianteService
	incidencia application.IncidenciaService
}

// --- Entrypoint ---

func main() {
	// 1. ConfiguraciÃ³n y logger
	cfg := mustLoadConfig()
	initLogger(cfg)

	// 2. Infraestructura (DB, encryptor, cache)
	infra := mustInitInfra(cfg)
	defer infra.sqlDB.Close()

	// 3. Servicios de aplicaciÃ³n
	services := initServices(cfg, infra)

	// 4. Servidor HTTP + graceful shutdown
	srv := initServer(cfg, services, infra)
	runGraceful(srv, infra.sqlDB)
}

// --- Paso 1: ConfiguraciÃ³n y Logger ---

func mustLoadConfig() *config.Config {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load configuration")
	}
	return cfg
}

func initLogger(cfg *config.Config) {
	if cfg.AppEnv == "production" {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Logger = log.Output(zerolog.NewConsoleWriter())
	}
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
}

// --- Paso 2: Infraestructura ---

func mustInitInfra(cfg *config.Config) *infraDeps {
	db, err := persistence.NewPostgresDB(cfg.DBDsn, cfg.MigrationDsn)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to PostgreSQL database")
	}

	sqlDB, err := db.DB()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get underlying sql.DB")
	}

	enc, err := crypto.NewEncryptor(cfg.EmailEncryptionKey)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize email encryptor")
	}

	// Cache en memoria para token_version: TTL de 30s reduce la ventana de stale-permissions
	// de 15 minutos (vida del JWT) a 30 segundos sin hits extra a Postgres por request.
	versionCache := cache.NewTokenVersionCache(30 * time.Second)

	fs, err := storage.NewLocalFileStorage(cfg.UploadDir)
	if err != nil {
		log.Fatal().Err(err).Str("dir", cfg.UploadDir).Msg("Failed to initialize file storage")
	}

	return &infraDeps{
		db:             db,
		sqlDB:          sqlDB,
		userRepo:       persistence.NewUserRepository(db),
		roleRepo:       persistence.NewRoleRepository(db),
		auditRepo:      persistence.NewAuditRepository(db),
		estudianteRepo: persistence.NewEstudianteRepository(db),
		incidenciaRepo: persistence.NewIncidenciaRepository(db),
		fileStorage:    fs,
		enc:            enc,
		versionCache:   versionCache,
	}
}

// --- Paso 3: Servicios de AplicaciÃ³n ---

func initServices(cfg *config.Config, infra *infraDeps) *appServices {
	return &appServices{
		auth:       application.NewAuthService(infra.userRepo, infra.roleRepo, cfg.JWTSecret, infra.enc),
		user:       application.NewUserService(infra.userRepo, infra.roleRepo, infra.enc, infra.versionCache, infra.auditRepo),
		role:       application.NewRoleService(infra.roleRepo, infra.userRepo, infra.versionCache, infra.auditRepo),
		estudiante: application.NewEstudianteService(infra.estudianteRepo, infra.enc, infra.auditRepo),
		incidencia: application.NewIncidenciaService(infra.incidenciaRepo, infra.fileStorage, infra.auditRepo),
	}
}

// --- Paso 4: Servidor HTTP ---

func initServer(cfg *config.Config, services *appServices, infra *infraDeps) *http.Server {
	authHandler := handlers.NewAuthHandler(services.auth)
	userHandler := handlers.NewUserHandler(services.user)
	roleHandler := handlers.NewRoleHandler(services.role)
	estudianteHandler := handlers.NewEstudianteHandler(services.estudiante)
	incidenciaHandler := handlers.NewIncidenciaHandler(services.incidencia)
	healthHandler := handlers.NewHealthHandler(infra.sqlDB)
	authMw := middleware.NewAuthMiddleware(cfg.JWTSecret, infra.userRepo, infra.versionCache)

	router := rest.NewRouter(authHandler, userHandler, roleHandler, estudianteHandler, incidenciaHandler, healthHandler, authMw, cfg.AppEnv, cfg.CORSOrigins)
	router.Use(middleware.RequestLogger())

	log.Info().Str("port", cfg.Port).Msg("Starting API server")

	return &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      router,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

// --- Paso 5: Graceful Shutdown ---

func runGraceful(srv *http.Server, sqlDB *sql.DB) {
	// Iniciar servidor en goroutine
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal().Err(err).Msg("Server stopped abruptly")
		}
	}()

	// Escuchar seÃ±ales del sistema operativo
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info().Msg("Shutting down server gracefully...")

	// Timeout de 10 segundos para que las peticiones en curso terminen
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("Server forced to shutdown")
	}

	// Cerrar conexiÃ³n a base de datos
	log.Info().Msg("Closing database connection...")
	if err := sqlDB.Close(); err != nil {
		log.Error().Err(err).Msg("Error closing database")
	}

	log.Info().Msg("Server exited properly")
}
