package application

import (
	"context"
	"errors"
	"fmt"

	"github.com/diego/go-api/internal/domain"
	"github.com/diego/go-api/internal/infrastructure/cache"
)

// RoleService define el contrato de la capa de aplicación para operaciones sobre roles y permisos.
// Centraliza la lógica de validación y orquestación, dejando los handlers libres de reglas de negocio.
type RoleService interface {
	// CreateRole crea un nuevo rol con el nombre y descripción indicados.
	// Retorna domain.ErrInvalidInput si el nombre está vacío.
	CreateRole(ctx context.Context, name, description string) (*domain.Role, error)

	// GetRoles retorna todos los roles del sistema con sus permisos asociados.
	GetRoles(ctx context.Context) ([]domain.Role, error)

	// GetRolesPaginated retorna una página de roles.
	GetRolesPaginated(ctx context.Context, page, size int) ([]domain.Role, error)

	// SearchRoles busca roles por nombre (case-insensitive).
	SearchRoles(ctx context.Context, query string) ([]domain.Role, error)

	// GetDeletedRoles retorna todos los roles soft-deleted.
	GetDeletedRoles(ctx context.Context) ([]domain.Role, error)

	// RestoreRole recupera un rol soft-deleted.
	RestoreRole(ctx context.Context, roleID uint) error

	// GetRoleByID retorna un rol por su ID primario.
	// Retorna domain.ErrRoleNotFound si no existe.
	GetRoleByID(ctx context.Context, id uint) (*domain.Role, error)

	// GetPermissions retorna todos los permisos disponibles en el sistema.
	GetPermissions(ctx context.Context) ([]domain.Permission, error)

	// GetPermissionsPaginated retorna una página de permisos.
	GetPermissionsPaginated(ctx context.Context, page, size int) ([]domain.Permission, error)

	// CreatePermission crea un nuevo permiso con nombre y descripción.
	// Retorna domain.ErrInvalidInput si el nombre está vacío.
	CreatePermission(ctx context.Context, name, description string) error

	// UpdatePermission actualiza nombre y descripción de un permiso.
	UpdatePermission(ctx context.Context, permID uint, name, description string) error

	// AssignPermissionsToRole reemplaza completamente los permisos de un rol.
	// Pasar un slice vacío elimina todos sus permisos.
	// Retorna domain.ErrRoleNotFound si el rol no existe,
	// domain.ErrInvalidInput si algún permissionID no existe en la base de datos.
	AssignPermissionsToRole(ctx context.Context, roleID uint, permissionIDs []uint) error

	// UpdateRole actualiza nombre y descripción de un rol existente.
	// Retorna domain.ErrRoleNotFound si no existe, domain.ErrInvalidInput si el nombre está vacío.
	UpdateRole(ctx context.Context, roleID uint, name, description string) error

	// DeleteRole elimina un rol del sistema.
	// Retorna domain.ErrRoleNotFound si no existe.
	DeleteRole(ctx context.Context, roleID uint) error
}

type roleService struct {
	repo         domain.RoleRepository
	userRepo     domain.UserRepository    // para invalidar tokens al cambiar permisos de un rol
	versionCache *cache.TokenVersionCache // nil-safe: invalidación explícita post-cambio
	audit        auditService
}

// NewRoleService construye un RoleService con sus dependencias inyectadas.
// userRepo se usa para incrementar token_version de los usuarios afectados cuando cambian los permisos de un rol.
// versionCache puede ser nil (el sistema funciona con el TTL del cache como ventana máxima).
// auditRepo puede ser nil (auditoría se ignora silenciosamente).
func NewRoleService(repo domain.RoleRepository, userRepo domain.UserRepository, versionCache *cache.TokenVersionCache, auditRepo domain.AuditRepository) RoleService {
	return &roleService{repo: repo, userRepo: userRepo, versionCache: versionCache, audit: newAuditService(auditRepo)}
}

// CreateRole valida que el nombre no sea vacío y que no exista ya en el sistema
// antes de persistir el nuevo rol.
// Retorna domain.ErrRoleAlreadyExists si ya existe un rol con ese nombre.
func (s *roleService) CreateRole(ctx context.Context, name, description string) (*domain.Role, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: role name cannot be empty", domain.ErrInvalidInput)
	}

	// Verificar unicidad antes de intentar el INSERT para retornar un error de dominio claro
	// en lugar de propagar el error de constraint de la base de datos.
	if _, err := s.repo.FindByName(ctx, name); err == nil {
		return nil, fmt.Errorf("%w: %s", domain.ErrRoleAlreadyExists, name)
	}

	role := &domain.Role{Name: name, Description: description}
	if err := s.repo.Create(ctx, role); err != nil {
		return nil, fmt.Errorf("failed to create role: %w", err)
	}

	s.audit.log(ctx, "create_role", "role", role.ID, nil, map[string]any{"name": role.Name, "description": description})
	return role, nil
}

// GetRoles retorna todos los roles con sus permisos pre-cargados.
// Respeta el scoping del actor: solo retorna roles de su scope o scope vacío.
func (s *roleService) GetRoles(ctx context.Context) ([]domain.Role, error) {
	actorScope, hasScope := ScopeFromContext(ctx)
	var roles []domain.Role
	var err error

	if hasScope && actorScope != "" {
		roles, err = s.repo.FindAllByScope(ctx, actorScope)
	} else {
		roles, err = s.repo.FindAll(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve roles: %w", err)
	}
	return roles, nil
}

// GetPermissions lista todos los permisos disponibles en el sistema.
func (s *roleService) GetPermissions(ctx context.Context) ([]domain.Permission, error) {
	perms, err := s.repo.FindAllPermissions(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve permissions: %w", err)
	}
	return perms, nil
}

// AssignPermissionsToRole valida la existencia del rol y de cada permiso antes de reemplazar
// la relación Many-to-Many. Un slice vacío de IDs es válido y limpia todos los permisos del rol.
// Tras actualizar, incrementa token_version de todos los usuarios con ese rol para invalidar
// sus JWT activos — incluso si los cambios son solo adiciones, se invalida por consistencia.
func (s *roleService) AssignPermissionsToRole(ctx context.Context, roleID uint, permissionIDs []uint) error {
	role, err := s.repo.FindByID(ctx, roleID)
	if err != nil {
		return fmt.Errorf("failed to get role: %w", err)
	}

	if len(permissionIDs) > 0 {
		perms, err := s.repo.FindPermissionsByIDs(ctx, permissionIDs)
		if err != nil {
			return fmt.Errorf("failed to get permissions: %w", err)
		}
		if len(perms) != len(permissionIDs) {
			return fmt.Errorf("%w: some permissions were not found", domain.ErrInvalidInput)
		}
		role.Permissions = perms
	} else {
		role.Permissions = []domain.Permission{}
	}

	oldPerms := make([]string, 0, len(role.Permissions))
	for _, p := range role.Permissions {
		oldPerms = append(oldPerms, p.Name)
	}

	if err := s.repo.Update(ctx, role); err != nil {
		return fmt.Errorf("failed to update role permissions: %w", err)
	}

	newPerms := make([]string, 0, len(role.Permissions))
	for _, p := range role.Permissions {
		newPerms = append(newPerms, p.Name)
	}

	s.audit.log(ctx, "assign_permissions", "role", role.ID,
		map[string]any{"permissions": oldPerms},
		map[string]any{"permissions": newPerms})

	// Invalidar los JWT de todos los usuarios que tengan este rol.
	// Primero incrementamos token_version en DB, luego limpiamos el cache en memoria
	// para que el efecto sea inmediato (sin esperar el TTL de 30s).
	userIDs, err := s.userRepo.FindUserIDsByRoleID(ctx, roleID)
	if err != nil {
		return fmt.Errorf("permissions updated but failed to find affected users: %w", err)
	}
	for _, uid := range userIDs {
		if _, err := s.userRepo.IncrementTokenVersion(ctx, uid); err != nil {
			return fmt.Errorf("failed to invalidate token for user %d: %w", uid, err)
		}
		if s.versionCache != nil {
			s.versionCache.Invalidate(uid)
		}
	}

	return nil
}

// GetRoleByID retorna el rol con sus permisos pre-cargados.
// Propaga ErrRoleNotFound si el ID no existe.
func (s *roleService) GetRoleByID(ctx context.Context, id uint) (*domain.Role, error) {
	role, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}
	return role, nil
}

// CreatePermission valida que el nombre no sea vacío y que no exista ya en el sistema.
// Retorna domain.ErrPermissionAlreadyExists si ya existe un permiso con ese nombre.
func (s *roleService) CreatePermission(ctx context.Context, name, description string) error {
	if name == "" {
		return fmt.Errorf("%w: permission name cannot be empty", domain.ErrInvalidInput)
	}

	// Verificar unicidad con búsqueda puntual en DB en lugar de cargar todos los permisos.
	existing, err := s.repo.FindPermissionByName(ctx, name)
	if err != nil && !errors.Is(err, domain.ErrPermissionNotFound) {
		return fmt.Errorf("failed to check permission uniqueness: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("%w: %s", domain.ErrPermissionAlreadyExists, name)
	}

	if err := s.repo.CreatePermissionWithDescription(ctx, name, description); err != nil {
		return fmt.Errorf("failed to create permission: %w", err)
	}

	// Para obtener el ID del permiso creado necesitamos buscarlo.
	perm, err := s.repo.FindPermissionByName(ctx, name)
	if err != nil {
		return fmt.Errorf("failed to retrieve created permission: %w", err)
	}

	s.audit.log(ctx, "create_permission", "permission", perm.ID, nil, map[string]any{"name": name, "description": description})
	return nil
}

// UpdateRole valida el nuevo nombre y reemplaza el campo en la base de datos.
// No modifica los permisos del rol — usar AssignPermissionsToRole para eso.
// Los roles de sistema (IsSystem) solo permiten cambiar descripción, NO nombre.
func (s *roleService) UpdateRole(ctx context.Context, roleID uint, name, description string) error {
	if name == "" {
		return fmt.Errorf("%w: role name cannot be empty", domain.ErrInvalidInput)
	}

	role, err := s.repo.FindByID(ctx, roleID)
	if err != nil {
		return fmt.Errorf("failed to find role: %w", err)
	}

	if err := assertScopeAccess(ctx, role.Scope); err != nil {
		return err
	}

	oldRole := map[string]any{"name": role.Name, "description": role.Description}

	if role.IsSystem && role.Name != name {
		return domain.ErrRoleImmutable
	}

	role.Name = name
	role.Description = description
	if err := s.repo.Update(ctx, role); err != nil {
		return fmt.Errorf("failed to update role: %w", err)
	}

	s.audit.log(ctx, "update_role", "role", role.ID, oldRole, map[string]any{"name": name, "description": description})
	return nil
}

// DeleteRole elimina el rol del sistema. Propaga ErrRoleNotFound si no existe.
// Rechaza ErrRoleImmutable si el rol es de sistema (Admin, User).
func (s *roleService) DeleteRole(ctx context.Context, roleID uint) error {
	role, err := s.repo.FindByID(ctx, roleID)
	if err != nil {
		return fmt.Errorf("failed to find role: %w", err)
	}

	if role.IsSystem {
		return domain.ErrRoleImmutable
	}

	if err := assertScopeAccess(ctx, role.Scope); err != nil {
		return err
	}

	if err := s.repo.Delete(ctx, roleID); err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}

	s.audit.log(ctx, "delete_role", "role", roleID,
		map[string]any{"id": role.ID, "name": role.Name}, nil)
	return nil
}

// GetRolesPaginated retorna una página de roles con sus permisos.
// Respeta el scoping del actor.
func (s *roleService) GetRolesPaginated(ctx context.Context, page, size int) ([]domain.Role, error) {
	if page < 1 {
		page = 1
	}
	if size <= 0 || size > 100 {
		size = 10
	}
	actorScope, hasScope := ScopeFromContext(ctx)
	var roles []domain.Role
	var err error

	if hasScope && actorScope != "" {
		roles, err = s.repo.FindAllPaginatedByScope(ctx, actorScope, page, size)
	} else {
		roles, err = s.repo.FindAllPaginated(ctx, page, size)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve roles: %w", err)
	}
	return roles, nil
}

// SearchRoles busca roles por nombre (case-insensitive).
// Respeta el scoping del actor.
func (s *roleService) SearchRoles(ctx context.Context, query string) ([]domain.Role, error) {
	if query == "" {
		return s.GetRoles(ctx)
	}
	actorScope, hasScope := ScopeFromContext(ctx)
	var roles []domain.Role
	var err error

	if hasScope && actorScope != "" {
		roles, err = s.repo.SearchByNameAndScope(ctx, query, actorScope)
	} else {
		roles, err = s.repo.SearchByName(ctx, query)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to search roles: %w", err)
	}
	return roles, nil
}

// GetDeletedRoles retorna todos los roles soft-deleted.
// Respeta el scoping del actor.
func (s *roleService) GetDeletedRoles(ctx context.Context) ([]domain.Role, error) {
	actorScope, hasScope := ScopeFromContext(ctx)
	var roles []domain.Role
	var err error

	if hasScope && actorScope != "" {
		roles, err = s.repo.FindAllDeletedByScope(ctx, actorScope)
	} else {
		roles, err = s.repo.FindAllDeleted(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve deleted roles: %w", err)
	}
	return roles, nil
}

// RestoreRole recupera un rol soft-deleted.
func (s *roleService) RestoreRole(ctx context.Context, roleID uint) error {
	if err := s.repo.Restore(ctx, roleID); err != nil {
		return fmt.Errorf("failed to restore role: %w", err)
	}
	s.audit.log(ctx, "restore_role", "role", roleID, nil, nil)
	return nil
}

// GetPermissionsPaginated retorna una página de permisos.
func (s *roleService) GetPermissionsPaginated(ctx context.Context, page, size int) ([]domain.Permission, error) {
	if page < 1 {
		page = 1
	}
	if size <= 0 || size > 100 {
		size = 10
	}
	perms, err := s.repo.FindAllPermissionsPaginated(ctx, page, size)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve permissions: %w", err)
	}
	return perms, nil
}

// UpdatePermission actualiza nombre y descripción de un permiso.
func (s *roleService) UpdatePermission(ctx context.Context, permID uint, name, description string) error {
	if name == "" {
		return fmt.Errorf("%w: permission name cannot be empty", domain.ErrInvalidInput)
	}

	perm, err := s.repo.FindPermissionByName(ctx, name)
	if err != nil && !errors.Is(err, domain.ErrPermissionNotFound) {
		return fmt.Errorf("failed to check permission: %w", err)
	}
	if perm != nil && perm.ID != permID {
		return fmt.Errorf("%w: %s", domain.ErrPermissionAlreadyExists, name)
	}

	if err := s.repo.UpdatePermission(ctx, &domain.Permission{ID: permID, Name: name, Description: description}); err != nil {
		return fmt.Errorf("failed to update permission: %w", err)
	}

	s.audit.log(ctx, "update_permission", "permission", permID,
		map[string]any{"name": perm.Name, "description": perm.Description},
		map[string]any{"name": name, "description": description})
	return nil
}
