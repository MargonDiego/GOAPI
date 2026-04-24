package http

import (
	"net/http"

	"github.com/gorilla/mux"
	httpSwagger "github.com/swaggo/http-swagger"

	"github.com/diego/go-api/internal/presentation/http/handlers"
	"github.com/diego/go-api/internal/presentation/http/middleware"
)

func NewRouter(
	authHandler *handlers.AuthHandler,
	userHandler *handlers.UserHandler,
	authMw *middleware.AuthMiddleware,
) *mux.Router {
	r := mux.NewRouter()

	// Swagger UI — disponible en /swagger/index.html
	r.PathPrefix("/swagger/").Handler(httpSwagger.WrapHandler)

	// Limitador estricto para rutas de autenticación (protege bcrypt):
	// 1 petición por segundo máximo, con ráfagas permitidas de hasta 5.
	authLimiter := middleware.NewIPRateLimiter(1, 5)

	r.Handle("/api/register", authLimiter.Middleware(http.HandlerFunc(authHandler.Register))).Methods("POST")
	r.Handle("/api/login", authLimiter.Middleware(http.HandlerFunc(authHandler.Login))).Methods("POST")
	r.Handle("/api/refresh", authLimiter.Middleware(http.HandlerFunc(authHandler.Refresh))).Methods("POST")

	api := r.PathPrefix("/api").Subrouter()
	api.Use(authMw.RequireAuth())

	api.HandleFunc("/me", userHandler.GetMe).Methods("GET")

	// Protected explicitly by read:users permission
	usersRoute := api.PathPrefix("/users").Subrouter()
	usersRoute.Use(authMw.RequirePermission("read:users"))
	usersRoute.HandleFunc("", userHandler.GetAll).Methods("GET")

	return r
}
