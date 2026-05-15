package rest

import (
	"net/http"

	"github.com/gorilla/mux"
	httpSwagger "github.com/swaggo/http-swagger"

	"github.com/diego/go-api/internal/presentation/rest/handlers"
	"github.com/diego/go-api/internal/presentation/rest/middleware"
)

func NewRouter(
	authHandler *handlers.AuthHandler,
	userHandler *handlers.UserHandler,
	roleHandler *handlers.RoleHandler,
	healthHandler *handlers.HealthHandler,
	authMw *middleware.AuthMiddleware,
	appEnv string,
	corsOrigins []string,
) *mux.Router {
	r := mux.NewRouter()

	// Middlewares globales — orden importa:
	// 1. PanicRecovery DEBE ser el más externo
	r.Use(middleware.PanicRecovery)
	// 2. RequestID para trazabilidad
	r.Use(middleware.RequestID)
	// 3. Security headers
	r.Use(middleware.SecurityHeaders(appEnv))
	// 4. CORS con orígenes configurables
	r.Use(middleware.CORS(corsOrigins...))

	// Swagger UI — disponible en /swagger/index.html
	r.PathPrefix("/swagger/").Handler(httpSwagger.WrapHandler)

	// Healthchecks (Kubernetes/Docker probes)
	r.HandleFunc("/health/liveness", healthHandler.Liveness).Methods("GET")
	r.HandleFunc("/health/readiness", healthHandler.Readiness).Methods("GET")

	// Rate limiting global para todas las rutas de la API (10 req/s, burst 20).
	// Protege contra DoS por usuarios autenticados ejecutando operaciones masivas.
	apiLimiter := middleware.NewIPRateLimiter(10, 20)

	// Limitador estricto para rutas de autenticación (protege bcrypt):
	// 1 petición por segundo máximo, con ráfagas permitidas de hasta 5.
	authLimiter := middleware.NewIPRateLimiter(1, 5)

	// Aplicar rate limiting global a todo /api/v1
	api := r.PathPrefix("/api/v1").Subrouter()
	api.Use(apiLimiter.Middleware)
	api.Use(authMw.RequireAuth())

	r.Handle("/api/v1/register", authLimiter.Middleware(http.HandlerFunc(authHandler.Register))).Methods("POST")
	r.Handle("/api/v1/login", authLimiter.Middleware(http.HandlerFunc(authHandler.Login))).Methods("POST")
	r.Handle("/api/v1/refresh", authLimiter.Middleware(http.HandlerFunc(authHandler.Refresh))).Methods("POST")

	// Logout: requiere auth + rate limit estricto
	api.Handle("/logout", authLimiter.Middleware(http.HandlerFunc(authHandler.Logout))).Methods("POST")

	api.HandleFunc("/me", userHandler.GetMe).Methods("GET")

	// Rutas de Usuarios
	usersRoute := api.PathPrefix("/users").Subrouter()
	// Lectura (rutas fijas primero para evitar captura por /{id})
	usersRoute.Handle("", authMw.RequirePermission("read:users")(http.HandlerFunc(userHandler.GetAll))).Methods("GET")
	usersRoute.Handle("/deleted", authMw.RequirePermission("manage:users")(http.HandlerFunc(userHandler.GetDeletedUsers))).Methods("GET")
	usersRoute.Handle("/{id}", authMw.RequirePermission("read:users")(http.HandlerFunc(userHandler.GetByID))).Methods("GET")
	// Creación
	usersRoute.Handle("", authMw.RequirePermission("manage:users")(http.HandlerFunc(userHandler.Create))).Methods("POST")
	// Modificación
	usersRoute.Handle("/{id}", authMw.RequirePermission("manage:users")(http.HandlerFunc(userHandler.Update))).Methods("PUT")
	usersRoute.Handle("/{id}", authMw.RequirePermission("manage:users")(http.HandlerFunc(userHandler.Delete))).Methods("DELETE")
	usersRoute.Handle("/{id}/restore", authMw.RequirePermission("manage:users")(http.HandlerFunc(userHandler.RestoreUser))).Methods("POST")
	usersRoute.Handle("/{id}/roles", authMw.RequirePermission("manage:roles")(http.HandlerFunc(userHandler.AssignRoles))).Methods("PUT")
	usersRoute.Handle("/bulk/roles", authMw.RequirePermission("manage:roles")(http.HandlerFunc(userHandler.BulkAssignRoles))).Methods("POST")

	// Rutas de Roles
	rolesRoute := api.PathPrefix("/roles").Subrouter()
	rolesRoute.Use(authMw.RequirePermission("manage:roles"))
	rolesRoute.HandleFunc("", roleHandler.CreateRole).Methods("POST")
	rolesRoute.HandleFunc("", roleHandler.GetRoles).Methods("GET")
	rolesRoute.HandleFunc("/deleted", roleHandler.GetDeletedRoles).Methods("GET")
	rolesRoute.HandleFunc("/{id}", roleHandler.GetRoleByID).Methods("GET")
	rolesRoute.HandleFunc("/{id}", roleHandler.UpdateRole).Methods("PUT")
	rolesRoute.HandleFunc("/{id}", roleHandler.DeleteRole).Methods("DELETE")
	rolesRoute.HandleFunc("/{id}/restore", roleHandler.RestoreRole).Methods("POST")
	rolesRoute.HandleFunc("/{id}/permissions", roleHandler.AssignPermissions).Methods("PUT")

	// Rutas de Permisos
	permsRoute := api.PathPrefix("/permissions").Subrouter()
	permsRoute.Use(authMw.RequirePermission("manage:roles"))
	permsRoute.HandleFunc("", roleHandler.GetPermissions).Methods("GET")
	permsRoute.HandleFunc("", roleHandler.CreatePermission).Methods("POST")

	return r
}
