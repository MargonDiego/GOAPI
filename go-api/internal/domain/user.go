package domain

import (
	"context"
	"errors"
	"strings"
	"time"
)

// Configuración de Account Lockout.
// Constantes exportadas para que puedan ser consultadas por los tests.
const (
	MaxFailedAttempts = 5               // Intentos antes del bloqueo
	LockDuration      = 15 * time.Minute // Duración del bloqueo
)

var (
	ErrUserNotFound      = errors.New("user not found")
	ErrInvalidCreds      = errors.New("invalid credentials")
	ErrUserAlreadyExists = errors.New("username already exists")
	ErrEmailAlreadyExists = errors.New("email already registered")
	ErrInsufficientPerms = errors.New("insufficient permissions")
	ErrInvalidInput      = errors.New("invalid user input data")
	ErrRoleNotFound      = errors.New("role not found")
	ErrInvalidToken      = errors.New("invalid or expired refresh token")
	ErrAccountLocked     = errors.New("account temporarily locked due to multiple failed attempts")
)

type Permission struct {
	ID   uint
	Name string
}

type Role struct {
	ID          uint
	Name        string
	Permissions []Permission
}

// User es la entidad central del dominio.
// El Email NUNCA llega aquí en texto plano desde la BD — se descifra en el servicio
// solo cuando es necesario mostrarlo (ej: endpoint de perfil).
// EmailEncrypted y EmailHash son los valores que viven en Postgres.
type User struct {
	ID             uint
	Username       string
	PasswordHash   string
	EmailEncrypted string    // AES-256-GCM, IV aleatorio, base64 — confidencialidad
	EmailHash      string    // HMAC-SHA256, determinista — permite WHERE email_hash = ?
	FailedAttempts int       // Contador de intentos fallidos consecutivos
	LockedUntil    *time.Time // nil = no bloqueado; not nil = bloqueado hasta esa hora
	Roles          []Role
}

type RefreshToken struct {
	Token     string
	UserID    uint
	ExpiresAt time.Time
}

// NewUser es la Fábrica (Factory) del Dominio Puro.
// Encapsula las invariantes de creación de usuario.
func NewUser(username, passwordHash string, defaultRole Role) (*User, error) {
	username = strings.TrimSpace(username)
	if len(username) < 3 {
		return nil, ErrInvalidInput
	}
	if passwordHash == "" {
		return nil, ErrInvalidInput
	}

	return &User{
		Username:     username,
		PasswordHash: passwordHash,
		Roles:        []Role{defaultRole},
	}, nil
}

// IsLocked informa si la cuenta está bloqueada EN ESTE MOMENTO.
// Separar esta lógica del servicio permite testearla sin infraestructura.
func (u *User) IsLocked() bool {
	if u.LockedUntil == nil {
		return false
	}
	return time.Now().Before(*u.LockedUntil)
}

// RecordFailedAttempt incrementa el contador y bloquea la cuenta si alcanza el máximo.
// Retorna true si la cuenta quedó bloqueada como consecuencia de ESTE intento.
func (u *User) RecordFailedAttempt() bool {
	u.FailedAttempts++
	if u.FailedAttempts >= MaxFailedAttempts {
		lockedUntil := time.Now().Add(LockDuration)
		u.LockedUntil = &lockedUntil
		return true
	}
	return false
}

// ResetFailedAttempts limpia el contador tras un login exitoso.
func (u *User) ResetFailedAttempts() {
	u.FailedAttempts = 0
	u.LockedUntil = nil
}

func (u *User) HasPermission(p string) bool {
	for _, r := range u.Roles {
		for _, perm := range r.Permissions {
			if perm.Name == p {
				return true
			}
		}
	}
	return false
}

type UserRepository interface {
	Save(ctx context.Context, u *User) error
	Update(ctx context.Context, u *User) error
	UpdateRoles(ctx context.Context, userID uint, roles []Role) error
	FindByUsername(ctx context.Context, username string) (*User, error)
	FindByID(ctx context.Context, id uint) (*User, error)
	FindByEmailHash(ctx context.Context, emailHash string) (*User, error)
	FindAll(ctx context.Context, page, size int) ([]User, error)
	FindRoleByName(ctx context.Context, roleName string) (Role, error)

	// Operaciones para Refresh Tokens
	SaveRefreshToken(ctx context.Context, rt *RefreshToken) error
	GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error)
	DeleteRefreshToken(ctx context.Context, token string) error
	DeleteAllRefreshTokens(ctx context.Context, userID uint) error
	Delete(ctx context.Context, id uint) error
}
