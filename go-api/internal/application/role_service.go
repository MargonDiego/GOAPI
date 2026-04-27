package application

import (
	"context"
	"fmt"

	"github.com/diego/go-api/internal/domain"
)

type RoleService interface {
	CreateRole(ctx context.Context, name string) (*domain.Role, error)
	GetRoles(ctx context.Context) ([]domain.Role, error)
	GetRoleByID(ctx context.Context, id uint) (*domain.Role, error)
	GetPermissions(ctx context.Context) ([]domain.Permission, error)
	CreatePermission(ctx context.Context, name string) error
	AssignPermissionsToRole(ctx context.Context, roleID uint, permissionIDs []uint) error
	UpdateRole(ctx context.Context, roleID uint, name string) error
	DeleteRole(ctx context.Context, roleID uint) error
}

type roleService struct {
	repo domain.RoleRepository
}

func NewRoleService(repo domain.RoleRepository) RoleService {
	return &roleService{repo: repo}
}

func (s *roleService) CreateRole(ctx context.Context, name string) (*domain.Role, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: role name cannot be empty", domain.ErrInvalidInput)
	}

	role := &domain.Role{Name: name}
	if err := s.repo.Create(ctx, role); err != nil {
		return nil, fmt.Errorf("failed to create role: %w", err)
	}
	return role, nil
}

func (s *roleService) GetRoles(ctx context.Context) ([]domain.Role, error) {
	roles, err := s.repo.FindAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve roles: %w", err)
	}
	return roles, nil
}

func (s *roleService) GetPermissions(ctx context.Context) ([]domain.Permission, error) {
	perms, err := s.repo.FindAllPermissions(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve permissions: %w", err)
	}
	return perms, nil
}

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

	return nil
}

func (s *roleService) GetRoleByID(ctx context.Context, id uint) (*domain.Role, error) {
	role, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}
	return role, nil
}

func (s *roleService) CreatePermission(ctx context.Context, name string) error {
	if name == "" {
		return fmt.Errorf("%w: permission name cannot be empty", domain.ErrInvalidInput)
	}

	if err := s.repo.CreatePermission(ctx, name); err != nil {
		return fmt.Errorf("failed to create permission: %w", err)
	}
	return nil
}

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

func (s *roleService) DeleteRole(ctx context.Context, roleID uint) error {
	if err := s.repo.Delete(ctx, roleID); err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}
	return nil
}
