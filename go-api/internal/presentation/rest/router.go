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
) *mux.Router {
	r := mux.NewRouter()

	r.Use(middleware.CORS())

	// Swagger UI — disponible en /swagger/index.html
	r.PathPrefix("/swagger/").Handler(httpSwagger.WrapHandler)

	// Healthchecks (Kubernetes/Docker probes)
	r.HandleFunc("/health/liveness", healthHandler.Liveness).Methods("GET")
	r.HandleFunc("/health/readiness", healthHandler.Readiness).Methods("GET")

	// Limitador estricto para rutas de autenticación (protege bcrypt):
	// 1 petición por segundo máximo, con ráfagas permitidas de hasta 5.
	authLimiter := middleware.NewIPRateLimiter(1, 5)

	r.Handle("/api/v1/register", authLimiter.Middleware(http.HandlerFunc(authHandler.Register))).Methods("POST")
	r.Handle("/api/v1/login", authLimiter.Middleware(http.HandlerFunc(authHandler.Login))).Methods("POST")
	r.Handle("/api/v1/refresh", authLimiter.Middleware(http.HandlerFunc(authHandler.Refresh))).Methods("POST")

	api := r.PathPrefix("/api/v1").Subrouter()
	api.Use(authMw.RequireAuth())

	// Logout requiere autenticación (necesita userID del contexto) + rate limiting
	api.Handle("/logout", authLimiter.Middleware(http.HandlerFunc(authHandler.Logout))).Methods("POST")

	api.HandleFunc("/me", userHandler.GetMe).Methods("GET")

	// Rutas de Usuarios
	usersRoute := api.PathPrefix("/users").Subrouter()
	// Lectura
	usersRoute.Handle("", authMw.RequirePermission("read:users")(http.HandlerFunc(userHandler.GetAll))).Methods("GET")
	usersRoute.Handle("/{id}", authMw.RequirePermission("read:users")(http.HandlerFunc(userHandler.GetByID))).Methods("GET")
	usersRoute.Handle("/deleted", authMw.RequirePermission("manage:users")(http.HandlerFunc(userHandler.GetDeletedUsers))).Methods("GET")
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
