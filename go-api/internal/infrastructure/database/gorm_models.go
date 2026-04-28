package database

import (
	"time"

	"github.com/diego/go-api/internal/domain"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username       string     `gorm:"uniqueIndex;not null"`
	Password       string     `gorm:"not null"`
	EmailEncrypted string     `gorm:"column:email_encrypted;not null;default:''"`
	EmailHash      string     `gorm:"column:email_hash;uniqueIndex;not null;default:''"`
	FailedAttempts int        `gorm:"column:failed_attempts;not null;default:0"`
	LockedUntil    *time.Time `gorm:"column:locked_until"`
	// TokenVersion se incrementa cada vez que cambian los roles/permisos del usuario.
	// El JWT embebe esta versión como claim "ver"; el middleware la valida en cada request.
	TokenVersion   int        `gorm:"column:token_version;not null;default:1"`
	Roles          []Role     `gorm:"many2many:user_roles;"`
}

type Role struct {
	gorm.Model
	Name        string       `gorm:"uniqueIndex;not null"`
	Permissions []Permission `gorm:"many2many:role_permissions;"`
}

type Permission struct {
	gorm.Model
	Name string `gorm:"uniqueIndex;not null"`
}

type RefreshToken struct {
	ID        uint      `gorm:"primarykey"`
	UserID    uint      `gorm:"not null"`
	Token     string    `gorm:"uniqueIndex;not null"`
	ExpiresAt time.Time `gorm:"not null"`
	CreatedAt time.Time
}

func toDomainUser(u *User) *domain.User {
	if u == nil {
		return nil
	}
	du := &domain.User{
		ID:             u.ID,
		Username:       u.Username,
		PasswordHash:   u.Password,
		EmailEncrypted: u.EmailEncrypted,
		EmailHash:      u.EmailHash,
		FailedAttempts: u.FailedAttempts,
		LockedUntil:    u.LockedUntil,
		TokenVersion:   u.TokenVersion,
		Roles:          make([]domain.Role, 0, len(u.Roles)),
	}

	for _, r := range u.Roles {
		dr := domain.Role{
			ID:          r.ID,
			Name:        r.Name,
			Permissions: make([]domain.Permission, 0, len(r.Permissions)),
		}
		for _, p := range r.Permissions {
			dr.Permissions = append(dr.Permissions, domain.Permission{ID: p.ID, Name: p.Name})
		}
		du.Roles = append(du.Roles, dr)
	}
	return du
}

func toDBUser(du *domain.User) *User {
	if du == nil {
		return nil
	}
	u := &User{
		Username:       du.Username,
		Password:       du.PasswordHash,
		EmailEncrypted: du.EmailEncrypted,
		EmailHash:      du.EmailHash,
		FailedAttempts: du.FailedAttempts,
		LockedUntil:    du.LockedUntil,
		TokenVersion:   du.TokenVersion,
		Roles:          make([]Role, 0, len(du.Roles)),
	}
	if du.ID != 0 {
		u.ID = du.ID
	}

	for _, r := range du.Roles {
		u.Roles = append(u.Roles, Role{
			Model: gorm.Model{ID: r.ID},
			Name:  r.Name,
		})
	}
	return u
}
