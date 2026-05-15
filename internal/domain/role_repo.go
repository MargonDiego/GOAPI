package domain

import "context"

type RoleRepository interface {
	Create(ctx context.Context, role *Role) error
	FindAll(ctx context.Context) ([]Role, error)
	FindAllByScope(ctx context.Context, scope string) ([]Role, error)
	FindAllPaginated(ctx context.Context, page, size int) ([]Role, error)
	FindAllPaginatedByScope(ctx context.Context, scope string, page, size int) ([]Role, error)
	FindByID(ctx context.Context, id uint) (*Role, error)
	FindByName(ctx context.Context, name string) (*Role, error)
	SearchByName(ctx context.Context, query string) ([]Role, error)
	SearchByNameAndScope(ctx context.Context, query, scope string) ([]Role, error)
	Update(ctx context.Context, role *Role) error
	Delete(ctx context.Context, id uint) error
	FindAllDeleted(ctx context.Context) ([]Role, error)
	FindAllDeletedByScope(ctx context.Context, scope string) ([]Role, error)
	Restore(ctx context.Context, id uint) error
	CreatePermission(ctx context.Context, name string) error
	CreatePermissionWithDescription(ctx context.Context, name, description string) error
	UpdatePermission(ctx context.Context, perm *Permission) error

	// Gestión de Permisos
	FindAllPermissions(ctx context.Context) ([]Permission, error)
	FindAllPermissionsPaginated(ctx context.Context, page, size int) ([]Permission, error)
	FindAllPermissionsPaginatedWithTotal(ctx context.Context, page, size int) (PaginatedResult[Permission], error)
	FindPermissionByName(ctx context.Context, name string) (*Permission, error)
	FindPermissionsByIDs(ctx context.Context, ids []uint) ([]Permission, error)
	FindRolesByIDs(ctx context.Context, ids []uint) ([]Role, error)
	// Contadores para metadatos de paginación
	CountRoles(ctx context.Context) (int64, error)
	CountRolesByScope(ctx context.Context, scope string) (int64, error)
	CountPermissions(ctx context.Context) (int64, error)
}
