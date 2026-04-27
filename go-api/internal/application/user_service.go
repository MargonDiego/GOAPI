package application

import (
	"context"
	"errors"
	"fmt"

	"github.com/diego/go-api/internal/domain"
	appcrypto "github.com/diego/go-api/internal/infrastructure/crypto"
)

type UserService interface {
	GetUserByUsername(ctx context.Context, username string) (*domain.User, error)
	GetAllUsers(ctx context.Context, page, size int) ([]domain.User, error)
	GetUserByID(ctx context.Context, id uint) (*domain.User, error)
	CreateUser(ctx context.Context, username, password, email string) error
	UpdateUser(ctx context.Context, userID uint, username, email string) error
	DeleteUser(ctx context.Context, userID uint) error
	AssignRolesToUser(ctx context.Context, userID uint, roleIDs []uint) error
}

type userService struct {
	repo     domain.UserRepository
	roleRepo domain.RoleRepository
	enc     *appcrypto.Encryptor
}

func NewUserService(repo domain.UserRepository, roleRepo domain.RoleRepository, enc *appcrypto.Encryptor) UserService {
	return &userService{repo: repo, roleRepo: roleRepo, enc: enc}
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

func (s *userService) GetUserByID(ctx context.Context, id uint) (*domain.User, error) {
	user, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return user, nil
}

func (s *userService) CreateUser(ctx context.Context, username, password, email string) error {
	_, err := s.repo.FindByUsername(ctx, username)
	if err == nil {
		return fmt.Errorf("%w: username already exists", domain.ErrUserAlreadyExists)
	}
	if !errors.Is(err, domain.ErrUserNotFound) {
		return fmt.Errorf("failed to check username: %w", err)
	}

	emailHash := ""
	if email != "" {
		emailHash = s.enc.HashEmail(email)
		_, err := s.repo.FindByEmailHash(ctx, emailHash)
		if err == nil {
			return fmt.Errorf("%w: email already exists", domain.ErrEmailAlreadyExists)
		}
		if !errors.Is(err, domain.ErrUserNotFound) {
			return fmt.Errorf("failed to check email: %w", err)
		}
	}

	defaultRole, err := s.roleRepo.FindByName(ctx, "User")
	if err != nil {
		return fmt.Errorf("failed to get default role: %w", err)
	}

	user, err := domain.NewUser(username, password, *defaultRole)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	if err := s.repo.Save(ctx, user); err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

func (s *userService) UpdateUser(ctx context.Context, userID uint, username, email string) error {
	user, err := s.repo.FindByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to find user: %w", err)
	}

	if username != "" {
		user.Username = username
	}

	if err := s.repo.Save(ctx, user); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

func (s *userService) DeleteUser(ctx context.Context, userID uint) error {
	if err := s.repo.Delete(ctx, userID); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	return nil
}
