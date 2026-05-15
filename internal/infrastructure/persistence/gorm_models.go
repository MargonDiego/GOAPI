package persistence

import (
	"time"

	"github.com/MargonDiego/GOAPI/internal/domain"
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
	Scope          string     `gorm:"index;default:''"`
	Roles          []Role     `gorm:"many2many:user_roles;"`
}

type Role struct {
	gorm.Model
	Name        string       `gorm:"uniqueIndex;not null"`
	Description string       `gorm:"type:text"`
	IsSystem    bool         `gorm:"not null;default:false"`
	Scope       string       `gorm:"index;default:''"`
	Permissions []Permission `gorm:"many2many:role_permissions;"`
}

type Permission struct {
	gorm.Model
	Name        string `gorm:"uniqueIndex;not null"`
	Description string `gorm:"type:text"`
}

type RefreshToken struct {
	ID        uint      `gorm:"primarykey"`
	UserID    uint      `gorm:"not null"`
	Token     string    `gorm:"uniqueIndex;not null"`
	ExpiresAt time.Time `gorm:"not null"`
	CreatedAt time.Time
}

// AuditLog registra cambios críticos en el sistema para trazabilidad forense.
type AuditLog struct {
	ID         uint      `gorm:"primarykey"`
	Action     string    `gorm:"not null;index"`
	ActorID    uint      `gorm:"not null;index"`
	TargetType string    `gorm:"not null"`
	TargetID   uint      `gorm:"not null"`
	OldValue   string    `gorm:"type:text"`
	NewValue   string    `gorm:"type:text"`
	IPAddress  string
	UserAgent  string
	CreatedAt  time.Time
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
		Scope:          u.Scope,
		Roles:          make([]domain.Role, 0, len(u.Roles)),
	}

	for _, r := range u.Roles {
		dr := domain.Role{
			ID:          r.ID,
			Name:        r.Name,
			Description: r.Description,
			Permissions: make([]domain.Permission, 0, len(r.Permissions)),
		}
		for _, p := range r.Permissions {
			dr.Permissions = append(dr.Permissions, domain.Permission{ID: p.ID, Name: p.Name, Description: p.Description})
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
		Scope:          du.Scope,
		Roles:          make([]Role, 0, len(du.Roles)),
	}
	if du.ID != 0 {
		u.ID = du.ID
	}

	for _, r := range du.Roles {
		u.Roles = append(u.Roles, Role{
			Model:       gorm.Model{ID: r.ID},
			Name:        r.Name,
			Description: r.Description,
		})
	}
	return u
}
