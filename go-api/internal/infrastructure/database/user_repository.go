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

// Update persiste cambios sobre un usuario existente.
// Usamos Select explícito para evitar sobrescribir campos sensibles por accidente
// (ej: no queremos que un update de intentos fallidos borre el password).
func (r *userRepository) Update(ctx context.Context, u *domain.User) error {
	result := r.db.WithContext(ctx).
		Model(&User{}).Where("id = ?", u.ID).
		Select("failed_attempts", "locked_until", "email_encrypted", "email_hash").
		Updates(map[string]any{
			"failed_attempts": u.FailedAttempts,
			"locked_until":    u.LockedUntil,
			"email_encrypted": u.EmailEncrypted,
			"email_hash":      u.EmailHash,
		})
	if result.Error != nil {
		return fmt.Errorf("repository unable to update user: %w", result.Error)
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

func (r *userRepository) FindByEmailHash(ctx context.Context, emailHash string) (*domain.User, error) {
	var u User
	if err := r.db.WithContext(ctx).Preload("Roles.Permissions").
		Where("email_hash = ?", emailHash).First(&u).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrUserNotFound
		}
		return nil, fmt.Errorf("database query error: %w", err)
	}
	return toDomainUser(&u), nil
}

func (r *userRepository) FindByID(ctx context.Context, id uint) (*domain.User, error) {
	var u User
	if err := r.db.WithContext(ctx).Preload("Roles.Permissions").First(&u, id).Error; err != nil {
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

func (r *userRepository) SaveRefreshToken(ctx context.Context, rt *domain.RefreshToken) error {
	dbRT := &RefreshToken{
		UserID:    rt.UserID,
		Token:     rt.Token,
		ExpiresAt: rt.ExpiresAt,
	}
	return r.db.WithContext(ctx).Create(dbRT).Error
}

func (r *userRepository) GetRefreshToken(ctx context.Context, token string) (*domain.RefreshToken, error) {
	var rt RefreshToken
	if err := r.db.WithContext(ctx).Where("token = ?", token).First(&rt).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrInvalidToken
		}
		return nil, fmt.Errorf("database query error: %w", err)
	}
	
	return &domain.RefreshToken{
		Token:     rt.Token,
		UserID:    rt.UserID,
		ExpiresAt: rt.ExpiresAt,
	}, nil
}

func (r *userRepository) DeleteRefreshToken(ctx context.Context, token string) error {
	return r.db.WithContext(ctx).Where("token = ?", token).Delete(&RefreshToken{}).Error
}
