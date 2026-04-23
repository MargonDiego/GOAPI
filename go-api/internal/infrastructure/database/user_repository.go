package database

import (
	"context"
	"errors"
	"fmt"

	"github.com/diego/go-api/internal/domain"
	"gorm.io/gorm"
)

type userRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) domain.UserRepository {
	return &userRepository{db: db}
}

func (r *userRepository) Save(ctx context.Context, u *domain.User) error {
	dbUser := toDBUser(u)
	
	if err := r.db.WithContext(ctx).Create(dbUser).Error; err != nil {
		return fmt.Errorf("repository unable to save user: %w", err)
	}
	return nil
}

func (r *userRepository) FindByUsername(ctx context.Context, username string) (*domain.User, error) {
	var u User
	if err := r.db.WithContext(ctx).Preload("Roles.Permissions").Where("username = ?", username).First(&u).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrUserNotFound
		}
		return nil, fmt.Errorf("database query error: %w", err)
	}
	return toDomainUser(&u), nil
}

func (r *userRepository) FindAll(ctx context.Context, page, size int) ([]domain.User, error) {
	var users []User
	offset := (page - 1) * size
	
	if err := r.db.WithContext(ctx).Preload("Roles.Permissions").Offset(offset).Limit(size).Find(&users).Error; err != nil {
		return nil, fmt.Errorf("database list user error: %w", err)
	}

	var dUsers []domain.User
	for _, u := range users {
		dUsers = append(dUsers, *toDomainUser(&u))
	}
	return dUsers, nil
}

func (r *userRepository) FindRoleByName(ctx context.Context, roleName string) (domain.Role, error) {
	var role Role
	if err := r.db.WithContext(ctx).Preload("Permissions").Where("name = ?", roleName).First(&role).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return domain.Role{}, domain.ErrRoleNotFound
		}
		return domain.Role{}, fmt.Errorf("database query error: %w", err)
	}
	
	dRole := domain.Role{ID: role.ID, Name: role.Name}
	for _, p := range role.Permissions {
		dRole.Permissions = append(dRole.Permissions, domain.Permission{ID: p.ID, Name: p.Name})
	}
	return dRole, nil
}
