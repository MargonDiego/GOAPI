package http

import (
	"github.com/gorilla/mux"

	"github.com/diego/go-api/internal/presentation/http/handlers"
	"github.com/diego/go-api/internal/presentation/http/middleware"
)

func NewRouter(
	authHandler *handlers.AuthHandler,
	userHandler *handlers.UserHandler,
	authMw *middleware.AuthMiddleware,
) *mux.Router {
	r := mux.NewRouter()

	r.HandleFunc("/api/register", authHandler.Register).Methods("POST")
	r.HandleFunc("/api/login", authHandler.Login).Methods("POST")

	api := r.PathPrefix("/api").Subrouter()
	api.Use(authMw.RequireAuth())

	api.HandleFunc("/me", userHandler.GetMe).Methods("GET")

	// Protected explicitly by read:users permission
	usersRoute := api.PathPrefix("/users").Subrouter()
	usersRoute.Use(authMw.RequirePermission("read:users"))
	usersRoute.HandleFunc("", userHandler.GetAll).Methods("GET")

	return r
}
