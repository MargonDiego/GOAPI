package handlers

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/diego/go-api/internal/application"
	"github.com/diego/go-api/internal/domain"
	"github.com/diego/go-api/internal/presentation/http/middleware"
)

// DTOs de respuesta tipados — más rápidos que map[string]interface{} para el encoder JSON
// y eliminan heap allocations de maps por cada request.
type permissionResponse struct {
	ID   uint   `json:"id"`
	Name string `json:"name"`
}

type roleResponse struct {
	ID          uint                 `json:"id"`
	Name        string               `json:"name"`
	Permissions []permissionResponse `json:"permissions"`
}

type userResponse struct {
	ID       uint           `json:"id"`
	Username string         `json:"username"`
	Roles    []roleResponse `json:"roles"`
}

type UserHandler struct {
	userService application.UserService
}

func NewUserHandler(s application.UserService) *UserHandler {
	return &UserHandler{userService: s}
}

// GetMe retorna el perfil del usuario autenticado.
//
// @Summary      Mi perfil
// @Description  Retorna los datos del usuario extraído del token JWT
// @Tags         users
// @Produce      json
// @Success      200 {object} userResponse
// @Failure      401 {object} ErrorResponse
// @Failure      404 {object} ErrorResponse
// @Security     BearerAuth
// @Router       /me [get]
func (h *UserHandler) GetMe(w http.ResponseWriter, r *http.Request) {
	username, ok := middleware.GetUsernameFromContext(r.Context())
	if !ok {
		RespondError(w, http.StatusUnauthorized, "user context missing")
		return
	}

	user, err := h.userService.GetUserByUsername(r.Context(), username)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			RespondError(w, http.StatusNotFound, err.Error())
			return
		}
		RespondError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	RespondJSON(w, http.StatusOK, toUserResponse(*user))
}

// GetAll lista todos los usuarios paginados.
//
// @Summary      Listar usuarios
// @Description  Retorna la lista paginada de usuarios. Requiere permiso read:users
// @Tags         users
// @Produce      json
// @Param        page query int false "Número de página" default(1)
// @Param        size query int false "Tamaño de página" default(10)
// @Success      200 {array}  userResponse
// @Failure      401 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
// @Security     BearerAuth
// @Router       /users [get]
func (h *UserHandler) GetAll(w http.ResponseWriter, r *http.Request) {
	page := parseQueryInt(r, "page", 1)
	size := parseQueryInt(r, "size", 10)

	users, err := h.userService.GetAllUsers(r.Context(), page, size)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "failed to list users")
		return
	}

	response := make([]userResponse, 0, len(users))
	for _, u := range users {
		response = append(response, toUserResponse(u))
	}

	RespondJSON(w, http.StatusOK, response)
}

// toUserResponse convierte un domain.User al DTO de respuesta tipado.
func toUserResponse(u domain.User) userResponse {
	roles := make([]roleResponse, 0, len(u.Roles))
	for _, r := range u.Roles {
		perms := make([]permissionResponse, 0, len(r.Permissions))
		for _, p := range r.Permissions {
			perms = append(perms, permissionResponse{ID: p.ID, Name: p.Name})
		}
		roles = append(roles, roleResponse{ID: r.ID, Name: r.Name, Permissions: perms})
	}
	return userResponse{ID: u.ID, Username: u.Username, Roles: roles}
}

// parseQueryInt abstrae el casteo y previene silent failures con fallbacks seguros.
func parseQueryInt(r *http.Request, key string, fallback int) int {
	valStr := r.URL.Query().Get(key)
	if valStr == "" {
		return fallback
	}
	val, err := strconv.Atoi(valStr)
	if err != nil || val <= 0 {
		return fallback
	}
	return val
}
