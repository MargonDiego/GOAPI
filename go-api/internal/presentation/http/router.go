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
	roleHandler *handlers.RoleHandler,
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

	// Users routes
	usersRoute := api.PathPrefix("/users").Subrouter()
	// Lectura
	usersRoute.Handle("", authMw.RequirePermission("read:users")(http.HandlerFunc(userHandler.GetAll))).Methods("GET")
	// Modificación
	usersRoute.Handle("/{id}/roles", authMw.RequirePermission("manage:roles")(http.HandlerFunc(userHandler.AssignRoles))).Methods("PUT")

	// Roles routes
	rolesRoute := api.PathPrefix("/roles").Subrouter()
	rolesRoute.Use(authMw.RequirePermission("manage:roles"))
	rolesRoute.HandleFunc("", roleHandler.CreateRole).Methods("POST")
	rolesRoute.HandleFunc("", roleHandler.GetRoles).Methods("GET")
	rolesRoute.HandleFunc("/{id}/permissions", roleHandler.AssignPermissions).Methods("PUT")

	// Permissions routes
	permsRoute := api.PathPrefix("/permissions").Subrouter()
	permsRoute.Use(authMw.RequirePermission("manage:roles"))
	permsRoute.HandleFunc("", roleHandler.GetPermissions).Methods("GET")

	return r
}
