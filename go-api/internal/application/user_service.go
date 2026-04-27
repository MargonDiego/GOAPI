package application

import (
	"context"
	"fmt"

	"github.com/diego/go-api/internal/domain"
)

type UserService interface {
	GetUserByUsername(ctx context.Context, username string) (*domain.User, error)
	GetAllUsers(ctx context.Context, page, size int) ([]domain.User, error)
	AssignRolesToUser(ctx context.Context, userID uint, roleIDs []uint) error
}

type userService struct {
	repo     domain.UserRepository
	roleRepo domain.RoleRepository
}

func NewUserService(repo domain.UserRepository, roleRepo domain.RoleRepository) UserService {
	return &userService{repo: repo, roleRepo: roleRepo}
}

func (s *userService) GetUserByUsername(ctx context.Context, username string) (*domain.User, error) {
	user, err := s.repo.FindByUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("failed to get user by username: %w", err)
	}
	return user, nil
}

func (s *userService) GetAllUsers(ctx context.Context, page, size int) ([]domain.User, error) {
	if page < 1 {
		page = 1
	}
	if size <= 0 || size > 100 {
		size = 10
	}

	users, err := s.repo.FindAll(ctx, page, size)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	return users, nil
}

func (s *userService) AssignRolesToUser(ctx context.Context, userID uint, roleIDs []uint) error {
	// Verificar existencia del usuario
	_, err := s.repo.FindByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to find user: %w", err)
	}

	// Obtener y validar roles
	var roles []domain.Role
	if len(roleIDs) > 0 {
		roles, err = s.roleRepo.FindRolesByIDs(ctx, roleIDs)
		if err != nil {
			return fmt.Errorf("failed to retrieve roles: %w", err)
		}
		if len(roles) != len(roleIDs) {
			return fmt.Errorf("%w: some roles were not found", domain.ErrInvalidInput)
		}
	}

	if err := s.repo.UpdateRoles(ctx, userID, roles); err != nil {
		return fmt.Errorf("failed to update user roles: %w", err)
	}

	return nil
}
