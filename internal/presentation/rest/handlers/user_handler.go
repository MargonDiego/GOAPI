package handlers

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/MargonDiego/GOAPI/internal/application"
	"github.com/MargonDiego/GOAPI/internal/domain"
	"github.com/MargonDiego/GOAPI/internal/presentation/rest/middleware"
	"github.com/rs/zerolog/log"
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
// @Description  Retorna los datos del usuario extraÃ­do del token JWT
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
		log.Error().Err(err).Msg("failed to get current user by username")
		RespondError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	RespondJSON(w, http.StatusOK, toUserResponse(*user))
}

// PaginatedUserResponse es la respuesta paginada de usuarios.
type PaginatedUserResponse struct {
	Data       []UserResponse `json:"data"`
	Page       int            `json:"page"`
	Size       int            `json:"size"`
	Total      int            `json:"total"`
	TotalPages int            `json:"total_pages"`
}

// GetAll lista usuarios paginados, con soporte de bÃºsqueda y filtro por rol.
//
// @Summary      Listar usuarios
// @Description  Retorna la lista paginada de usuarios. Soporta bÃºsqueda (?search=) y filtro por rol (?role=).
// @Tags         users
// @Produce      json
// @Param        page query int false "NÃºmero de pÃ¡gina" default(1)
// @Param        size query int false "TamaÃ±o de pÃ¡gina" default(10)
// @Param        search query string false "Buscar por username/email"
// @Param        role query string false "Filtrar por nombre de rol"
// @Success      200 {object} PaginatedUserResponse
// @Failure      401 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
// @Failure      500 {object} ErrorResponse
// @Security     BearerAuth
// @Router       /users [get]
func (h *UserHandler) GetAll(w http.ResponseWriter, r *http.Request) {
	page := parseQueryInt(r, "page", 1)
	size := parseQueryInt(r, "size", 10)
	search := r.URL.Query().Get("search")
	roleName := r.URL.Query().Get("role")

	var result domain.PaginatedResult[domain.User]
	var err error

	if search != "" || roleName != "" {
		result, err = h.userService.SearchUsers(r.Context(), search, roleName, page, size)
	} else {
		result, err = h.userService.GetAllUsers(r.Context(), page, size)
	}

	if err != nil {
		log.Error().Err(err).Msg("failed to list users")
		RespondError(w, http.StatusInternalServerError, "failed to list users")
		return
	}

	response := make([]UserResponse, 0, len(result.Data))
	for _, u := range result.Data {
		response = append(response, toUserResponse(u))
	}

	if response == nil {
		response = []UserResponse{}
	}

	RespondJSON(w, http.StatusOK, PaginatedUserResponse{
		Data:       response,
		Page:       result.Page,
		Size:       result.Size,
		Total:      result.Total,
		TotalPages: result.TotalPages,
	})
}

// AssignRolesRequest es el DTO para asignar roles a un usuario.
type AssignRolesRequest struct {
	RoleIDs []uint `json:"role_ids" validate:"required,dive,gt=0" example:"1,2"`
}

// BulkAssignRolesRequest es el DTO para asignar roles a mÃºltiples usuarios.
type BulkAssignRolesRequest struct {
	UserIDs []uint `json:"user_ids" validate:"required,dive,gt=0" example:"1,2,3"`
	RoleIDs []uint `json:"role_ids" validate:"required,dive,gt=0" example:"4,5"`
}

// AssignRoles asigna uno o mÃ¡s roles a un usuario.
//
// @Summary      Asignar roles a usuario
// @Description  Actualiza los roles asociados a un usuario especÃ­fico. Un array vacÃ­o elimina todos los roles.
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
// @Failure      404 {object} ErrorResponse
// @Failure      500 {object} ErrorResponse
// @Router       /users/{id}/roles [put]
func (h *UserHandler) AssignRoles(w http.ResponseWriter, r *http.Request) {
	userID, err := getIDFromURL(r, "id")
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	var req AssignRolesRequest
	if errs := DecodeAndValidate(r, &req); len(errs) > 0 {
		RespondJSON(w, http.StatusBadRequest, map[string]interface{}{"errors": errs})
		return
	}

	if err := h.userService.AssignRolesToUser(withActor(r), uint(userID), req.RoleIDs); err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			RespondError(w, http.StatusNotFound, err.Error())
			return
		}
		if errors.Is(err, domain.ErrInvalidInput) {
			RespondError(w, http.StatusBadRequest, err.Error())
			return
		}
		log.Error().Err(err).Msg("failed to assign roles")
		RespondError(w, http.StatusInternalServerError, "failed to assign roles")
		return
	}

	RespondJSON(w, http.StatusOK, MessageResponse{Message: "roles assigned successfully"})
}

// BulkAssignRoles asigna roles a mÃºltiples usuarios en una sola operaciÃ³n.
//
// @Summary      Asignar roles en bulk
// @Description  Asigna los mismos roles a mÃºltiples usuarios simultÃ¡neamente. Valida existencia y scoping.
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        body body BulkAssignRolesRequest true "IDs de usuarios y roles"
// @Security     BearerAuth
// @Success      200 {object} MessageResponse
// @Failure      400 {object} ErrorResponse
// @Failure      401 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
// @Failure      500 {object} ErrorResponse
// @Router       /users/bulk/roles [post]
func (h *UserHandler) BulkAssignRoles(w http.ResponseWriter, r *http.Request) {
	var req BulkAssignRolesRequest
	if errs := DecodeAndValidate(r, &req); len(errs) > 0 {
		RespondJSON(w, http.StatusBadRequest, map[string]interface{}{"errors": errs})
		return
	}

	if err := h.userService.BulkAssignRolesToUsers(withActor(r), req.UserIDs, req.RoleIDs); err != nil {
		if errors.Is(err, domain.ErrInvalidInput) {
			RespondError(w, http.StatusBadRequest, err.Error())
			return
		}
		if errors.Is(err, domain.ErrScopeMismatch) {
			RespondError(w, http.StatusForbidden, err.Error())
			return
		}
		log.Error().Err(err).Msg("failed to bulk assign roles")
		RespondError(w, http.StatusInternalServerError, "failed to bulk assign roles")
		return
	}

	RespondJSON(w, http.StatusOK, MessageResponse{Message: "roles assigned to users successfully"})
}

// CreateUserRequest es el DTO para crear usuario.
type CreateUserRequest struct {
	Username string `json:"username" validate:"required,min=3,max=50" example:"johndoe"`
	Password string `json:"password" validate:"required,min=8,max=72" example:"secret1234"`
	Email    string `json:"email,omitempty" validate:"omitempty,email" example:"johndoe@example.com"`
}

// GetByID Obtiene un usuario por su ID.
//
// @Summary      Obtener usuario por ID
// @Description  Retorna los datos de un usuario especÃ­fico
// @Tags         users
// @Produce      json
// @Param        id path int true "User ID"
// @Success      200 {object} UserResponse
// @Failure      400 {object} ErrorResponse
// @Failure      401 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
// @Failure      404 {object} ErrorResponse
// @Failure      500 {object} ErrorResponse
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
		log.Error().Err(err).Msg("failed to get user by ID")
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
	if errs := DecodeAndValidate(r, &req); len(errs) > 0 {
		RespondJSON(w, http.StatusBadRequest, map[string]interface{}{"errors": errs})
		return
	}

	err := h.userService.CreateUser(withActor(r), req.Username, req.Password, req.Email)
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
	Username string `json:"username,omitempty" validate:"omitempty,min=3,max=50" example:"johndoe"`
	Email    string `json:"email,omitempty" validate:"omitempty,email" example:"johndoe@example.com"`
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
	if errs := DecodeAndValidate(r, &req); len(errs) > 0 {
		RespondJSON(w, http.StatusBadRequest, map[string]interface{}{"errors": errs})
		return
	}

	if req.Username == "" && req.Email == "" {
		RespondError(w, http.StatusBadRequest, "at least one field to update is required")
		return
	}

	err = h.userService.UpdateUser(withActor(r), uint(id), req.Username, req.Email)
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

	err = h.userService.DeleteUser(withActor(r), uint(id))
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			RespondError(w, http.StatusNotFound, err.Error())
			return
		}
		log.Error().Err(err).Msg("failed to delete user")
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
			perms = append(perms, PermissionResponse{ID: p.ID, Name: p.Name, Description: p.Description})
		}
		roles = append(roles, RoleResponse{ID: r.ID, Name: r.Name, Description: r.Description, Permissions: perms})
	}
	return UserResponse{ID: u.ID, Username: u.Username, Roles: roles}
}

// GetDeletedUsers lista todos los usuarios soft-deleted.
//
// @Summary      Listar usuarios eliminados
// @Description  Obtiene todos los usuarios que fueron soft-deleted
// @Tags         users
// @Produce      json
// @Security     BearerAuth
// @Success      200 {array} UserResponse
// @Failure      401 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
// @Failure      500 {object} ErrorResponse
// @Router       /users/deleted [get]
func (h *UserHandler) GetDeletedUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.userService.GetDeletedUsers(r.Context())
	if err != nil {
		log.Error().Err(err).Msg("failed to get deleted users")
		RespondError(w, http.StatusInternalServerError, "failed to get deleted users")
		return
	}

	response := make([]UserResponse, 0, len(users))
	for _, u := range users {
		response = append(response, toUserResponse(u))
	}

	RespondJSON(w, http.StatusOK, response)
}

// RestoreUser recupera un usuario soft-deleted.
//
// @Summary      Restaurar usuario
// @Description  Recupera un usuario que fue soft-deleted
// @Tags         users
// @Produce      json
// @Param        id path int true "User ID"
// @Security     BearerAuth
// @Success      200 {object} MessageResponse
// @Failure      400 {object} ErrorResponse
// @Failure      401 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
// @Failure      404 {object} ErrorResponse
// @Failure      500 {object} ErrorResponse
// @Router       /users/{id}/restore [post]
func (h *UserHandler) RestoreUser(w http.ResponseWriter, r *http.Request) {
	id, err := getIDFromURL(r, "id")
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	if err := h.userService.RestoreUser(withActor(r), uint(id)); err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			RespondError(w, http.StatusNotFound, err.Error())
			return
		}
		log.Error().Err(err).Msg("failed to restore user")
		RespondError(w, http.StatusInternalServerError, "failed to restore user")
		return
	}

	RespondJSON(w, http.StatusOK, MessageResponse{Message: "user restored successfully"})
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
