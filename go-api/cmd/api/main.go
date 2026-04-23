package main

import (
	"log"
	"net/http"
	"os"

	"github.com/diego/go-api/internal/application"
	"github.com/diego/go-api/internal/infrastructure/database"
	mypresentation "github.com/diego/go-api/internal/presentation/http"
	"github.com/diego/go-api/internal/presentation/http/handlers"
	"github.com/diego/go-api/internal/presentation/http/middleware"
)

func main() {
	// Entorno y Configuración
	jwtSecret := []byte(getEnv("JWT_SECRET", "super_secret_key_change_me_in_prod"))
	port := getEnv("PORT", "8080")
	// Usamos tu string de conexión de Supabase por defecto si no hay variable inyectada.
	defaultDSN := "postgresql://postgres:**Microservicios1324@db.cwkqhgmwoydxwztnrtdn.supabase.co:5432/postgres"
	dsn := getEnv("DB_DSN", defaultDSN)

	// 1. Capa de Infraestructura (Base de datos PostgreSQL en Supabase)
	db, err := database.NewPostgresDB(dsn)
	if err != nil {
		log.Fatalf("Failed to connect to PostgreSQL database: %v", err)
	}
	userRepo := database.NewUserRepository(db)

	// 2. Capa de Aplicación (Servicios de dominio)
	authService := application.NewAuthService(userRepo, jwtSecret)
	userService := application.NewUserService(userRepo)

	// 3. Capa de Presentación HTTP (Middlewares y Controladores)
	authHandler := handlers.NewAuthHandler(authService)
	userHandler := handlers.NewUserHandler(userService)
	authMw := middleware.NewAuthMiddleware(jwtSecret)

	// Inicialización de Router
	router := mypresentation.NewRouter(authHandler, userHandler, authMw)

	log.Printf("Starting Clean Architecture Go API on :%s", port)
	if err := http.ListenAndServe(":"+port, router); err != nil {
		log.Fatalf("Server stopped abruptly: %v", err)
	}
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

