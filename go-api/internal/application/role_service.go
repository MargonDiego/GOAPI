package application

import (
	"context"
	"fmt"

	"github.com/diego/go-api/internal/domain"
	"github.com/diego/go-api/internal/infrastructure/cache"
)

// RoleService define el contrato de la capa de aplicación para operaciones sobre roles y permisos.
// Centraliza la lógica de validación y orquestación, dejando los handlers libres de reglas de negocio.
type RoleService interface {
	// CreateRole crea un nuevo rol con el nombre indicado.
	// Retorna domain.ErrInvalidInput si el nombre está vacío.
	CreateRole(ctx context.Context, name string) (*domain.Role, error)

	// GetRoles retorna todos los roles del sistema con sus permisos asociados.
	GetRoles(ctx context.Context) ([]domain.Role, error)

	// GetRoleByID retorna un rol por su ID primario.
	// Retorna domain.ErrRoleNotFound si no existe.
	GetRoleByID(ctx context.Context, id uint) (*domain.Role, error)

	// GetPermissions retorna todos los permisos disponibles en el sistema.
	GetPermissions(ctx context.Context) ([]domain.Permission, error)

	// CreatePermission crea un nuevo permiso con el nombre indicado (ej: "read:posts").
	// Retorna domain.ErrInvalidInput si el nombre está vacío.
	CreatePermission(ctx context.Context, name string) error

	// AssignPermissionsToRole reemplaza completamente los permisos de un rol.
	// Pasar un slice vacío elimina todos sus permisos.
	// Retorna domain.ErrRoleNotFound si el rol no existe,
	// domain.ErrInvalidInput si algún permissionID no existe en la base de datos.
	AssignPermissionsToRole(ctx context.Context, roleID uint, permissionIDs []uint) error

	// UpdateRole actualiza el nombre de un rol existente.
	// Retorna domain.ErrRoleNotFound si no existe, domain.ErrInvalidInput si el nombre está vacío.
	UpdateRole(ctx context.Context, roleID uint, name string) error

	// DeleteRole elimina un rol del sistema.
	// Retorna domain.ErrRoleNotFound si no existe.
	DeleteRole(ctx context.Context, roleID uint) error
}

type roleService struct {
	repo         domain.RoleRepository
	userRepo     domain.UserRepository        // para invalidar tokens al cambiar permisos de un rol
	versionCache *cache.TokenVersionCache     // nil-safe: invalidación explícita post-cambio
}

// NewRoleService construye un RoleService con sus dependencias inyectadas.
// userRepo se usa para incrementar token_version de los usuarios afectados cuando cambian los permisos de un rol.
// versionCache puede ser nil (el sistema funciona con el TTL del cache como ventana máxima).
func NewRoleService(repo domain.RoleRepository, userRepo domain.UserRepository, versionCache *cache.TokenVersionCache) RoleService {
	return &roleService{repo: repo, userRepo: userRepo, versionCache: versionCache}
}

// CreateRole valida que el nombre no sea vacío y que no exista ya en el sistema
// antes de persistir el nuevo rol.
// Retorna domain.ErrRoleAlreadyExists si ya existe un rol con ese nombre.
func (s *roleService) CreateRole(ctx context.Context, name string) (*domain.Role, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: role name cannot be empty", domain.ErrInvalidInput)
	}

	// Verificar unicidad antes de intentar el INSERT para retornar un error de dominio claro
	// en lugar de propagar el error de constraint de la base de datos.
	if _, err := s.repo.FindByName(ctx, name); err == nil {
		return nil, fmt.Errorf("%w: %s", domain.ErrRoleAlreadyExists, name)
	}

	role := &domain.Role{Name: name}
	if err := s.repo.Create(ctx, role); err != nil {
		return nil, fmt.Errorf("failed to create role: %w", err)
	}
	return role, nil
}

// GetRoles retorna todos los roles con sus permisos pre-cargados.
func (s *roleService) GetRoles(ctx context.Context) ([]domain.Role, error) {
	roles, err := s.repo.FindAll(ctx)
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

	if err := s.repo.Update(ctx, role); err != nil {
		return fmt.Errorf("failed to update role permissions: %w", err)
	}

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
// Nota: los permisos son un conjunto pequeño y acotado, por lo que la búsqueda lineal es aceptable.
func (s *roleService) CreatePermission(ctx context.Context, name string) error {
	if name == "" {
		return fmt.Errorf("%w: permission name cannot be empty", domain.ErrInvalidInput)
	}

	// Verificar unicidad para retornar un error de dominio claro en lugar del constraint de DB.
	perms, err := s.repo.FindAllPermissions(ctx)
	if err != nil {
		return fmt.Errorf("failed to check permission uniqueness: %w", err)
	}
	for _, p := range perms {
		if p.Name == name {
			return fmt.Errorf("%w: %s", domain.ErrPermissionAlreadyExists, name)
		}
	}

	if err := s.repo.CreatePermission(ctx, name); err != nil {
		return fmt.Errorf("failed to create permission: %w", err)
	}
	return nil
}

// UpdateRole valida el nuevo nombre y reemplaza el campo en la base de datos.
// No modifica los permisos del rol — usar AssignPermissionsToRole para eso.
func (s *roleService) UpdateRole(ctx context.Context, roleID uint, name string) error {
	if name == "" {
		return fmt.Errorf("%w: role name cannot be empty", domain.ErrInvalidInput)
	}

	role, err := s.repo.FindByID(ctx, roleID)
	if err != nil {
		return fmt.Errorf("failed to find role: %w", err)
	}

	role.Name = name
	if err := s.repo.Update(ctx, role); err != nil {
		return fmt.Errorf("failed to update role: %w", err)
	}

	return nil
}

// DeleteRole elimina el rol del sistema. Propaga ErrRoleNotFound si no existe.
func (s *roleService) DeleteRole(ctx context.Context, roleID uint) error {
	if err := s.repo.Delete(ctx, roleID); err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}
	return nil
}
