package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/diego/go-api/internal/application"
	"github.com/diego/go-api/internal/infrastructure/database"
	mypresentation "github.com/diego/go-api/internal/presentation/http"
	"github.com/diego/go-api/internal/presentation/http/handlers"
	"github.com/diego/go-api/internal/presentation/http/middleware"

	// Importación anónima para auto-cargar variables desde el archivo .env (si existe)
	_ "github.com/joho/godotenv/autoload"
)

func main() {
	// Entorno y Configuración: Validaciones estrictas
	jwtSecret := []byte(os.Getenv("JWT_SECRET"))
	if len(jwtSecret) == 0 {
		log.Fatal("FATAL ERROR: JWT_SECRET env var is not set")
	}

	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		log.Fatal("FATAL ERROR: DB_DSN env var is not set (Production credentials cannot be hardcoded)")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

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

	// Servidor HTTP con mitigaciones defensivas (Timeouts para prevenir Slowloris)
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      router,
		ReadTimeout:  5 * time.Second,   // Corta clientes lentos/maliciosos en lectura
		WriteTimeout: 10 * time.Second,  // Corta si la respuesta se tarda en escribir al cliente
		IdleTimeout:  120 * time.Second, // Recicla conexiones Keep-Alive inactivas
	}

	log.Printf("Starting Clean Architecture Go API securely on :%s", port)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("Server stopped abruptly: %v", err)
	}
}
