package domain

import "context"

type RoleRepository interface {
	Create(ctx context.Context, role *Role) error
	FindAll(ctx context.Context) ([]Role, error)
	FindByID(ctx context.Context, id uint) (*Role, error)
	FindByName(ctx context.Context, name string) (*Role, error)
	Update(ctx context.Context, role *Role) error
	Delete(ctx context.Context, id uint) error
	CreatePermission(ctx context.Context, name string) error

	// Gestión de Permisos
	FindAllPermissions(ctx context.Context) ([]Permission, error)
	FindPermissionsByIDs(ctx context.Context, ids []uint) ([]Permission, error)
	FindRolesByIDs(ctx context.Context, ids []uint) ([]Role, error)
}
