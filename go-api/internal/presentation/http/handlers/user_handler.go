package handlers

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/diego/go-api/internal/application"
	"github.com/diego/go-api/internal/domain"
	"github.com/diego/go-api/internal/presentation/http/middleware"
)

type UserHandler struct {
	userService application.UserService
}

func NewUserHandler(s application.UserService) *UserHandler {
	return &UserHandler{userService: s}
}

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

	RespondJSON(w, http.StatusOK, map[string]interface{}{
		"id":       user.ID,
		"username": user.Username,
		"roles":    user.Roles,
	})
}

func (h *UserHandler) GetAll(w http.ResponseWriter, r *http.Request) {
	page := parseQueryInt(r, "page", 1)
	size := parseQueryInt(r, "size", 10)

	users, err := h.userService.GetAllUsers(r.Context(), page, size)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "failed to list users")
		return
	}

	// Pre-aloja capacidad para reducir allocations de memoria
	response := make([]map[string]interface{}, 0, len(users))
	for _, u := range users {
		response = append(response, map[string]interface{}{
			"id":       u.ID,
			"username": u.Username,
			"roles":    u.Roles,
		})
	}

	RespondJSON(w, http.StatusOK, response)
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
