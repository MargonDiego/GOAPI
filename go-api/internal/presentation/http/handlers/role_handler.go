package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/diego/go-api/internal/application"
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
// @Description  Crea un nuevo rol en el sistema
// @Tags         roles
// @Accept       json
// @Produce      json
// @Param        body body RoleCreateRequest true "Datos del rol"
// @Security     BearerAuth
// @Success      201 {object} RoleResponse
// @Failure      400 {object} ErrorResponse
// @Failure      401 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
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

	var res []RoleResponse
	for _, role := range roles {
		var perms []PermissionResponse
		for _, p := range role.Permissions {
			perms = append(perms, PermissionResponse{ID: p.ID, Name: p.Name})
		}
		res = append(res, RoleResponse{
			ID:          role.ID,
			Name:        role.Name,
			Permissions: perms,
		})
	}

	// Si no hay roles, devolver array vacío en vez de null
	if res == nil {
		res = []RoleResponse{}
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

	var res []PermissionResponse
	for _, p := range perms {
		res = append(res, PermissionResponse{ID: p.ID, Name: p.Name})
	}

	if res == nil {
		res = []PermissionResponse{}
	}

	RespondJSON(w, http.StatusOK, res)
}

// AssignPermissions asigna permisos a un rol.
//
// @Summary      Asignar permisos a rol
// @Description  Actualiza los permisos asociados a un rol específico
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
		RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	RespondJSON(w, http.StatusOK, MessageResponse{Message: "permissions assigned successfully"})
}
