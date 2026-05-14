package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/diego/go-api/internal/application"
	"github.com/diego/go-api/internal/domain"
)

// RoleCreateRequest es el DTO para crear un rol.
type RoleCreateRequest struct {
	Name string `json:"name" example:"Editor"`
}

// AssignPermissionsRequest es el DTO para asignar permisos a un rol.
type AssignPermissionsRequest struct {
	PermissionIDs []uint `json:"permission_ids" example:"1,2,3"`
}

// PermissionResponse es la respuesta de un Permiso.
type PermissionResponse struct {
	ID   uint   `json:"id"`
	Name string `json:"name"`
}

// RoleResponse es la respuesta de un Rol.
type RoleResponse struct {
	ID          uint                 `json:"id"`
	Name        string               `json:"name"`
	Permissions []PermissionResponse `json:"permissions"`
}

type RoleHandler struct {
	roleService application.RoleService
}

func NewRoleHandler(s application.RoleService) *RoleHandler {
	return &RoleHandler{roleService: s}
}

// CreateRole crea un nuevo rol.
//
// @Summary      Crear un rol
// @Description  Crea un nuevo rol en el sistema. Retorna 409 si el nombre ya existe.
// @Tags         roles
// @Accept       json
// @Produce      json
// @Param        body body RoleCreateRequest true "Datos del rol"
// @Security     BearerAuth
// @Success      201 {object} RoleResponse
// @Failure      400 {object} ErrorResponse
// @Failure      401 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
// @Failure      409 {object} ErrorResponse
// @Failure      500 {object} ErrorResponse
// @Router       /roles [post]
func (h *RoleHandler) CreateRole(w http.ResponseWriter, r *http.Request) {
	var req RoleCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "invalid json payload")
		return
	}

	role, err := h.roleService.CreateRole(r.Context(), req.Name)
	if err != nil {
		if errors.Is(err, domain.ErrRoleAlreadyExists) {
			RespondError(w, http.StatusConflict, err.Error())
			return
		}
		RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	RespondJSON(w, http.StatusCreated, RoleResponse{
		ID:          role.ID,
		Name:        role.Name,
		Permissions: []PermissionResponse{},
	})
}

// GetRoles lista todos los roles.
//
// @Summary      Listar roles
// @Description  Obtiene todos los roles con sus permisos asociados
// @Tags         roles
// @Produce      json
// @Security     BearerAuth
// @Success      200 {array} RoleResponse
// @Failure      401 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
// @Failure      500 {object} ErrorResponse
// @Router       /roles [get]
func (h *RoleHandler) GetRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := h.roleService.GetRoles(r.Context())
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "failed to get roles")
		return
	}

	res := make([]RoleResponse, 0, len(roles))
	for _, role := range roles {
		// Inicializar como slice vacío para serializar [] en vez de null cuando no hay permisos.
		perms := make([]PermissionResponse, 0, len(role.Permissions))
		for _, p := range role.Permissions {
			perms = append(perms, PermissionResponse{ID: p.ID, Name: p.Name})
		}
		res = append(res, RoleResponse{
			ID:          role.ID,
			Name:        role.Name,
			Permissions: perms,
		})
	}

	RespondJSON(w, http.StatusOK, res)
}

// GetPermissions lista todos los permisos.
//
// @Summary      Listar permisos
// @Description  Obtiene todos los permisos disponibles en el sistema
// @Tags         roles
// @Produce      json
// @Security     BearerAuth
// @Success      200 {array} PermissionResponse
// @Failure      401 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
// @Failure      500 {object} ErrorResponse
// @Router       /permissions [get]
func (h *RoleHandler) GetPermissions(w http.ResponseWriter, r *http.Request) {
	perms, err := h.roleService.GetPermissions(r.Context())
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "failed to get permissions")
		return
	}

	res := make([]PermissionResponse, 0, len(perms))
	for _, p := range perms {
		res = append(res, PermissionResponse{ID: p.ID, Name: p.Name})
	}

	RespondJSON(w, http.StatusOK, res)
}

// AssignPermissions asigna permisos a un rol.
//
// @Summary      Asignar permisos a rol
// @Description  Reemplaza completamente los permisos de un rol. Un array vacío elimina todos los permisos.
// @Tags         roles
// @Accept       json
// @Produce      json
// @Param        id path int true "Role ID"
// @Param        body body AssignPermissionsRequest true "IDs de los permisos"
// @Security     BearerAuth
// @Success      200 {object} MessageResponse
// @Failure      400 {object} ErrorResponse
// @Failure      401 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
// @Failure      404 {object} ErrorResponse
// @Failure      500 {object} ErrorResponse
// @Router       /roles/{id}/permissions [put]
func (h *RoleHandler) AssignPermissions(w http.ResponseWriter, r *http.Request) {
	roleID, err := getIDFromURL(r, "id")
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid role id")
		return
	}

	var req AssignPermissionsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "invalid json payload")
		return
	}

	if err := h.roleService.AssignPermissionsToRole(r.Context(), uint(roleID), req.PermissionIDs); err != nil {
		if errors.Is(err, domain.ErrRoleNotFound) {
			RespondError(w, http.StatusNotFound, err.Error())
			return
		}
		if errors.Is(err, domain.ErrInvalidInput) {
			RespondError(w, http.StatusBadRequest, err.Error())
			return
		}
		RespondError(w, http.StatusInternalServerError, "failed to assign permissions")
		return
	}

	RespondJSON(w, http.StatusOK, MessageResponse{Message: "permissions assigned successfully"})
}

// GetRoleByID Obtiene un rol por su ID.
//
// @Summary      Obtener rol por ID
// @Description  Retorna los datos de un rol específico
// @Tags         roles
// @Produce      json
// @Param        id path int true "Role ID"
// @Success      200 {object} RoleResponse
// @Failure      400 {object} ErrorResponse
// @Failure      401 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
// @Failure      404 {object} ErrorResponse
// @Failure      500 {object} ErrorResponse
// @Security     BearerAuth
// @Router       /roles/{id} [get]
func (h *RoleHandler) GetRoleByID(w http.ResponseWriter, r *http.Request) {
	id, err := getIDFromURL(r, "id")
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid role id")
		return
	}

	role, err := h.roleService.GetRoleByID(r.Context(), uint(id))
	if err != nil {
		if errors.Is(err, domain.ErrRoleNotFound) {
			RespondError(w, http.StatusNotFound, err.Error())
			return
		}
		RespondError(w, http.StatusInternalServerError, "failed to get role")
		return
	}

	// Inicializar como slice vacío para serializar [] en vez de null cuando no hay permisos.
	perms := make([]PermissionResponse, 0, len(role.Permissions))
	for _, p := range role.Permissions {
		perms = append(perms, PermissionResponse{ID: p.ID, Name: p.Name})
	}

	RespondJSON(w, http.StatusOK, RoleResponse{
		ID:          role.ID,
		Name:        role.Name,
		Permissions: perms,
	})
}

// RoleUpdateRequest es el DTO para actualizar un rol.
type RoleUpdateRequest struct {
	Name string `json:"name,omitempty" example:"Editor"`
}

// UpdateRole actualiza un rol existente.
//
// @Summary      Actualizar rol
// @Description  Actualiza los datos de un rol existente
// @Tags         roles
// @Accept       json
// @Produce      json
// @Param        id path int true "Role ID"
// @Param        body body RoleUpdateRequest true "Datos a actualizar"
// @Security     BearerAuth
// @Success      200 {object} MessageResponse
// @Failure      400 {object} ErrorResponse
// @Failure      401 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
// @Failure      404 {object} ErrorResponse
// @Router       /roles/{id} [put]
func (h *RoleHandler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	id, err := getIDFromURL(r, "id")
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid role id")
		return
	}

	var req RoleUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "invalid json payload")
		return
	}

	if req.Name == "" {
		RespondError(w, http.StatusBadRequest, "role name is required")
		return
	}

	err = h.roleService.UpdateRole(r.Context(), uint(id), req.Name)
	if err != nil {
		if errors.Is(err, domain.ErrRoleNotFound) {
			RespondError(w, http.StatusNotFound, err.Error())
			return
		}
		RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	RespondJSON(w, http.StatusOK, MessageResponse{Message: "role updated successfully"})
}

// DeleteRole elimina un rol existente.
//
// @Summary      Eliminar rol
// @Description  Elimina un rol del sistema
// @Tags         roles
// @Produce      json
// @Param        id path int true "Role ID"
// @Security     BearerAuth
// @Success      200 {object} MessageResponse
// @Failure      400 {object} ErrorResponse
// @Failure      401 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
// @Failure      404 {object} ErrorResponse
// @Router       /roles/{id} [delete]
func (h *RoleHandler) DeleteRole(w http.ResponseWriter, r *http.Request) {
	id, err := getIDFromURL(r, "id")
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid role id")
		return
	}

	err = h.roleService.DeleteRole(r.Context(), uint(id))
	if err != nil {
		if errors.Is(err, domain.ErrRoleNotFound) {
			RespondError(w, http.StatusNotFound, err.Error())
			return
		}
		RespondError(w, http.StatusInternalServerError, "failed to delete role")
		return
	}

	RespondJSON(w, http.StatusOK, MessageResponse{Message: "role deleted successfully"})
}

// PermissionCreateRequest es el DTO para crear un permiso.
type PermissionCreateRequest struct {
	Name string `json:"name" example:"read:posts"`
}

// CreatePermission crea un nuevo permiso.
//
// @Summary      Crear permiso
// @Description  Crea un nuevo permiso en el sistema. Retorna 409 si el nombre ya existe.
// @Tags         permissions
// @Accept       json
// @Produce      json
// @Param        body body PermissionCreateRequest true "Datos del permiso"
// @Security     BearerAuth
// @Success      201 {object} MessageResponse
// @Failure      400 {object} ErrorResponse
// @Failure      401 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
// @Failure      409 {object} ErrorResponse
// @Router       /permissions [post]
func (h *RoleHandler) CreatePermission(w http.ResponseWriter, r *http.Request) {
	var req PermissionCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "invalid json payload")
		return
	}

	if req.Name == "" {
		RespondError(w, http.StatusBadRequest, "permission name is required")
		return
	}

	err := h.roleService.CreatePermission(r.Context(), req.Name)
	if err != nil {
		if errors.Is(err, domain.ErrPermissionAlreadyExists) {
			RespondError(w, http.StatusConflict, err.Error())
			return
		}
		RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	RespondJSON(w, http.StatusCreated, MessageResponse{Message: "permission created successfully"})
}
