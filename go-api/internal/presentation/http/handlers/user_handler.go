package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/diego/go-api/internal/application"
	"github.com/diego/go-api/internal/domain"
	"github.com/diego/go-api/internal/presentation/http/middleware"
)

type UserResponse struct {
	ID       uint           `json:"id"`
	Username string         `json:"username"`
	Roles    []RoleResponse `json:"roles"`
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
// @Success      200 {object} UserResponse
// @Failure      401 {object} ErrorResponse
// @Failure      404 {object} ErrorResponse
// @Failure      500 {object} ErrorResponse
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
// @Success      200 {array}  UserResponse
// @Failure      401 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
// @Failure      500 {object} ErrorResponse
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

	response := make([]UserResponse, 0, len(users))
	for _, u := range users {
		response = append(response, toUserResponse(u))
	}

	if response == nil {
		response = []UserResponse{}
	}

	RespondJSON(w, http.StatusOK, response)
}

// AssignRolesRequest es el DTO para asignar roles a un usuario.
type AssignRolesRequest struct {
	RoleIDs []uint `json:"role_ids" example:"1,2"`
}

// AssignRoles asigna uno o más roles a un usuario.
//
// @Summary      Asignar roles a usuario
// @Description  Actualiza los roles asociados a un usuario específico
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        id path int true "User ID"
// @Param        body body AssignRolesRequest true "IDs de los roles"
// @Security     BearerAuth
// @Success      200 {object} MessageResponse
// @Failure      400 {object} ErrorResponse
// @Failure      401 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
// @Failure      500 {object} ErrorResponse
// @Router       /users/{id}/roles [put]
func (h *UserHandler) AssignRoles(w http.ResponseWriter, r *http.Request) {
	userID, err := getIDFromURL(r, "id")
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	var req AssignRolesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "invalid json payload")
		return
	}

	if err := h.userService.AssignRolesToUser(r.Context(), uint(userID), req.RoleIDs); err != nil {
		RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	RespondJSON(w, http.StatusOK, MessageResponse{Message: "roles assigned successfully"})
}

// CreateUserRequest es el DTO para crear usuario.
type CreateUserRequest struct {
	Username string `json:"username" example:"johndoe"`
	Password string `json:"password" example:"secret1234"`
	Email    string `json:"email,omitempty" example:"johndoe@example.com"`
}

// GetByID Obtiene un usuario por su ID.
//
// @Summary      Obtener usuario por ID
// @Description  Retorna los datos de un usuario específico
// @Tags         users
// @Produce      json
// @Param        id path int true "User ID"
// @Success      200 {object} UserResponse
// @Failure      401 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
// @Failure      404 {object} ErrorResponse
// @Security     BearerAuth
// @Router       /users/{id} [get]
func (h *UserHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	id, err := getIDFromURL(r, "id")
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	user, err := h.userService.GetUserByID(r.Context(), uint(id))
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

// Create crea un nuevo usuario.
//
// @Summary      Crear usuario
// @Description  Crea un nuevo usuario en el sistema
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        body body CreateUserRequest true "Datos del nuevo usuario"
// @Security     BearerAuth
// @Success      201 {object} MessageResponse
// @Failure      400 {object} ErrorResponse
// @Failure      401 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
// @Failure      409 {object} ErrorResponse
// @Router       /users [post]
func (h *UserHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "invalid json payload")
		return
	}

	if req.Username == "" || req.Password == "" {
		RespondError(w, http.StatusBadRequest, "username and password are required")
		return
	}

	err := h.userService.CreateUser(r.Context(), req.Username, req.Password, req.Email)
	if err != nil {
		if errors.Is(err, domain.ErrUserAlreadyExists) || errors.Is(err, domain.ErrEmailAlreadyExists) {
			RespondError(w, http.StatusConflict, err.Error())
			return
		}
		RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	RespondJSON(w, http.StatusCreated, MessageResponse{Message: "user created successfully"})
}

// UpdateUserRequest es el DTO para actualizar usuario.
type UpdateUserRequest struct {
	Username string `json:"username,omitempty" example:"johndoe"`
	Email    string `json:"email,omitempty" example:"johndoe@example.com"`
}

// Update actualiza un usuario existente.
//
// @Summary      Actualizar usuario
// @Description  Actualiza los datos de un usuario existente
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        id path int true "User ID"
// @Param        body body UpdateUserRequest true "Datos a actualizar"
// @Security     BearerAuth
// @Success      200 {object} MessageResponse
// @Failure      400 {object} ErrorResponse
// @Failure      401 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
// @Failure      404 {object} ErrorResponse
// @Router       /users/{id} [put]
func (h *UserHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := getIDFromURL(r, "id")
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	var req UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "invalid json payload")
		return
	}

	if req.Username == "" && req.Email == "" {
		RespondError(w, http.StatusBadRequest, "at least one field to update is required")
		return
	}

	err = h.userService.UpdateUser(r.Context(), uint(id), req.Username, req.Email)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			RespondError(w, http.StatusNotFound, err.Error())
			return
		}
		RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	RespondJSON(w, http.StatusOK, MessageResponse{Message: "user updated successfully"})
}

// Delete elimina un usuario existente.
//
// @Summary      Eliminar usuario
// @Description  Elimina un usuario del sistema
// @Tags         users
// @Produce      json
// @Param        id path int true "User ID"
// @Security     BearerAuth
// @Success      200 {object} MessageResponse
// @Failure      400 {object} ErrorResponse
// @Failure      401 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
// @Failure      404 {object} ErrorResponse
// @Router       /users/{id} [delete]
func (h *UserHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := getIDFromURL(r, "id")
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	err = h.userService.DeleteUser(r.Context(), uint(id))
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			RespondError(w, http.StatusNotFound, err.Error())
			return
		}
		RespondError(w, http.StatusInternalServerError, "failed to delete user")
		return
	}

	RespondJSON(w, http.StatusOK, MessageResponse{Message: "user deleted successfully"})
}

// toUserResponse convierte un domain.User al DTO de respuesta tipado.
func toUserResponse(u domain.User) UserResponse {
	roles := make([]RoleResponse, 0, len(u.Roles))
	for _, r := range u.Roles {
		perms := make([]PermissionResponse, 0, len(r.Permissions))
		for _, p := range r.Permissions {
			perms = append(perms, PermissionResponse{ID: p.ID, Name: p.Name})
		}
		roles = append(roles, RoleResponse{ID: r.ID, Name: r.Name, Permissions: perms})
	}
	return UserResponse{ID: u.ID, Username: u.Username, Roles: roles}
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
