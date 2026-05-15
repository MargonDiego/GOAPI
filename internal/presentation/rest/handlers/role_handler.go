package handlers

import (
	"errors"
	"net/http"

	"github.com/MargonDiego/GOAPI/internal/application"
	"github.com/MargonDiego/GOAPI/internal/domain"
	"github.com/rs/zerolog/log"
)

// RoleCreateRequest es el DTO para crear un rol.
type RoleCreateRequest struct {
	Name        string `json:"name" validate:"required,min=2,max=50" example:"Editor"`
	Description string `json:"description,omitempty" validate:"omitempty,max=500" example:"Can edit content"`
}

// AssignPermissionsRequest es el DTO para asignar permisos a un rol.
type AssignPermissionsRequest struct {
	PermissionIDs []uint `json:"permission_ids" validate:"required,dive,gt=0" example:"1,2,3"`
}

// PermissionResponse es la respuesta de un Permiso.
type PermissionResponse struct {
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// RoleResponse es la respuesta de un Rol.
type RoleResponse struct {
	ID          uint                 `json:"id"`
	Name        string               `json:"name"`
	Description string               `json:"description,omitempty"`
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
	if errs := DecodeAndValidate(r, &req); len(errs) > 0 {
		RespondJSON(w, http.StatusBadRequest, map[string]interface{}{"errors": errs})
		return
	}

	role, err := h.roleService.CreateRole(withActor(r), req.Name, req.Description)
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
		Description: role.Description,
		Permissions: []PermissionResponse{},
	})
}

// PaginatedRoleResponse es la respuesta paginada de roles.
type PaginatedRoleResponse struct {
	Data       []RoleResponse `json:"data"`
	Page       int            `json:"page"`
	Size       int            `json:"size"`
	Total      int            `json:"total"`
	TotalPages int            `json:"total_pages"`
}

// GetRoles lista todos los roles, con soporte opcional de paginación y búsqueda.
//
// @Summary      Listar roles
// @Description  Obtiene roles con sus permisos. Soporta paginación (?page=&size=) y búsqueda (?search=).
// @Tags         roles
// @Produce      json
// @Param        page query int false "Número de página" default(1)
// @Param        size query int false "Tamaño de página" default(10)
// @Param        search query string false "Buscar por nombre"
// @Security     BearerAuth
// @Success      200 {object} PaginatedRoleResponse
// @Failure      401 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
// @Failure      500 {object} ErrorResponse
// @Router       /roles [get]
func (h *RoleHandler) GetRoles(w http.ResponseWriter, r *http.Request) {
	search := r.URL.Query().Get("search")
	page := parseQueryInt(r, "page", 0)
	size := parseQueryInt(r, "size", 0)

	var result domain.PaginatedResult[domain.Role]
	var err error

	if search != "" {
		roles, err := h.roleService.SearchRoles(r.Context(), search)
		if err != nil {
			log.Error().Err(err).Msg("failed to search roles")
			RespondError(w, http.StatusInternalServerError, "failed to search roles")
			return
		}
		result = domain.NewPaginatedResult(roles, 1, len(roles), len(roles))
	} else if page > 0 && size > 0 {
		result, err = h.roleService.GetRolesPaginated(r.Context(), page, size)
		if err != nil {
			log.Error().Err(err).Msg("failed to get roles paginated")
			RespondError(w, http.StatusInternalServerError, "failed to get roles")
			return
		}
	} else {
		roles, err := h.roleService.GetRoles(r.Context())
		if err != nil {
			log.Error().Err(err).Msg("failed to get roles")
			RespondError(w, http.StatusInternalServerError, "failed to get roles")
			return
		}
		result = domain.NewPaginatedResult(roles, 1, len(roles), len(roles))
	}

	res := make([]RoleResponse, 0, len(result.Data))
	for _, role := range result.Data {
		// Inicializar como slice vacío para serializar [] en vez de null cuando no hay permisos.
		perms := make([]PermissionResponse, 0, len(role.Permissions))
		for _, p := range role.Permissions {
			perms = append(perms, PermissionResponse{ID: p.ID, Name: p.Name, Description: p.Description})
		}
		res = append(res, RoleResponse{
			ID:          role.ID,
			Name:        role.Name,
			Description: role.Description,
			Permissions: perms,
		})
	}

	RespondJSON(w, http.StatusOK, PaginatedRoleResponse{
		Data:       res,
		Page:       result.Page,
		Size:       result.Size,
		Total:      result.Total,
		TotalPages: result.TotalPages,
	})
}

// GetPermissions lista permisos, con soporte opcional de paginación.
//
// @Summary      Listar permisos
// @Description  Obtiene todos los permisos disponibles. Soporta paginación (?page=&size=).
// @Tags         roles
// @Produce      json
// @Param        page query int false "Número de página" default(1)
// @Param        size query int false "Tamaño de página" default(10)
// @Security     BearerAuth
// @Success      200 {object} PaginatedPermissionResponse
// @Failure      401 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
// @Failure      500 {object} ErrorResponse
// @Router       /permissions [get]
func (h *RoleHandler) GetPermissions(w http.ResponseWriter, r *http.Request) {
	page := parseQueryInt(r, "page", 0)
	size := parseQueryInt(r, "size", 0)

	var result domain.PaginatedResult[domain.Permission]
	var err error

	if page > 0 && size > 0 {
		result, err = h.roleService.GetPermissionsPaginated(r.Context(), page, size)
	} else {
		var perms []domain.Permission
		perms, err = h.roleService.GetPermissions(r.Context())
		result = domain.NewPaginatedResult(perms, 1, len(perms), len(perms))
	}

	if err != nil {
		log.Error().Err(err).Msg("failed to get permissions")
		RespondError(w, http.StatusInternalServerError, "failed to get permissions")
		return
	}

	res := make([]PermissionResponse, 0, len(result.Data))
	for _, p := range result.Data {
		res = append(res, PermissionResponse{ID: p.ID, Name: p.Name, Description: p.Description})
	}

	RespondJSON(w, http.StatusOK, map[string]any{
		"data":        res,
		"page":        result.Page,
		"size":        result.Size,
		"total":       result.Total,
		"total_pages": result.TotalPages,
	})
}

// PaginatedPermissionResponse es la respuesta paginada de permisos.
type PaginatedPermissionResponse struct {
	Data       []PermissionResponse `json:"data"`
	Page       int                  `json:"page"`
	Size       int                  `json:"size"`
	Total      int                  `json:"total"`
	TotalPages int                  `json:"total_pages"`
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
	if errs := DecodeAndValidate(r, &req); len(errs) > 0 {
		RespondJSON(w, http.StatusBadRequest, map[string]interface{}{"errors": errs})
		return
	}

	if err := h.roleService.AssignPermissionsToRole(withActor(r), uint(roleID), req.PermissionIDs); err != nil {
		if errors.Is(err, domain.ErrRoleNotFound) {
			RespondError(w, http.StatusNotFound, err.Error())
			return
		}
		if errors.Is(err, domain.ErrInvalidInput) {
			RespondError(w, http.StatusBadRequest, err.Error())
			return
		}
		log.Error().Err(err).Msg("failed to assign permissions")
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
		log.Error().Err(err).Msg("failed to get role")
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
		Description: role.Description,
		Permissions: perms,
	})
}

// RoleUpdateRequest es el DTO para actualizar un rol.
type RoleUpdateRequest struct {
	Name        string `json:"name" validate:"required,min=2,max=50" example:"Editor"`
	Description string `json:"description,omitempty" validate:"omitempty,max=500" example:"Can edit content"`
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
	if errs := DecodeAndValidate(r, &req); len(errs) > 0 {
		RespondJSON(w, http.StatusBadRequest, map[string]interface{}{"errors": errs})
		return
	}

	err = h.roleService.UpdateRole(withActor(r), uint(id), req.Name, req.Description)
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

	err = h.roleService.DeleteRole(withActor(r), uint(id))
	if err != nil {
		if errors.Is(err, domain.ErrRoleNotFound) {
			RespondError(w, http.StatusNotFound, err.Error())
			return
		}
		log.Error().Err(err).Msg("failed to delete role")
		RespondError(w, http.StatusInternalServerError, "failed to delete role")
		return
	}

	RespondJSON(w, http.StatusOK, MessageResponse{Message: "role deleted successfully"})
}

// PermissionCreateRequest es el DTO para crear un permiso.
type PermissionCreateRequest struct {
	Name        string `json:"name" validate:"required,min=3,max=100" example:"read:posts"`
	Description string `json:"description,omitempty" validate:"omitempty,max=500" example:"Allows reading posts"`
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
	if errs := DecodeAndValidate(r, &req); len(errs) > 0 {
		RespondJSON(w, http.StatusBadRequest, map[string]interface{}{"errors": errs})
		return
	}

	err := h.roleService.CreatePermission(withActor(r), req.Name, req.Description)
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

// GetDeletedRoles lista todos los roles soft-deleted.
//
// @Summary      Listar roles eliminados
// @Description  Obtiene todos los roles que fueron soft-deleted
// @Tags         roles
// @Produce      json
// @Security     BearerAuth
// @Success      200 {array} RoleResponse
// @Failure      401 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
// @Failure      500 {object} ErrorResponse
// @Router       /roles/deleted [get]
func (h *RoleHandler) GetDeletedRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := h.roleService.GetDeletedRoles(r.Context())
	if err != nil {
		log.Error().Err(err).Msg("failed to get deleted roles")
		RespondError(w, http.StatusInternalServerError, "failed to get deleted roles")
		return
	}

	res := make([]RoleResponse, 0, len(roles))
	for _, role := range roles {
		perms := make([]PermissionResponse, 0, len(role.Permissions))
		for _, p := range role.Permissions {
			perms = append(perms, PermissionResponse{ID: p.ID, Name: p.Name, Description: p.Description})
		}
		res = append(res, RoleResponse{
			ID:          role.ID,
			Name:        role.Name,
			Description: role.Description,
			Permissions: perms,
		})
	}

	RespondJSON(w, http.StatusOK, res)
}

// RestoreRole recupera un rol soft-deleted.
//
// @Summary      Restaurar rol
// @Description  Recupera un rol que fue soft-deleted
// @Tags         roles
// @Produce      json
// @Param        id path int true "Role ID"
// @Security     BearerAuth
// @Success      200 {object} MessageResponse
// @Failure      400 {object} ErrorResponse
// @Failure      401 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
// @Failure      404 {object} ErrorResponse
// @Failure      500 {object} ErrorResponse
// @Router       /roles/{id}/restore [post]
func (h *RoleHandler) RestoreRole(w http.ResponseWriter, r *http.Request) {
	id, err := getIDFromURL(r, "id")
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid role id")
		return
	}

	if err := h.roleService.RestoreRole(withActor(r), uint(id)); err != nil {
		if errors.Is(err, domain.ErrRoleNotFound) {
			RespondError(w, http.StatusNotFound, err.Error())
			return
		}
		log.Error().Err(err).Msg("failed to restore role")
		RespondError(w, http.StatusInternalServerError, "failed to restore role")
		return
	}

	RespondJSON(w, http.StatusOK, MessageResponse{Message: "role restored successfully"})
}
