package domain

import (
	"context"
	"errors"
	"strings"
)

var (
	ErrUserNotFound      = errors.New("user not found")
	ErrInvalidCreds      = errors.New("invalid credentials")
	ErrUserAlreadyExists = errors.New("username already exists")
	ErrInsufficientPerms = errors.New("insufficient permissions")
	ErrInvalidInput      = errors.New("invalid user input data")
	ErrRoleNotFound      = errors.New("role not found")
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

type User struct {
	ID           uint
	Username     string
	PasswordHash string
	Roles        []Role
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
	FindByUsername(ctx context.Context, username string) (*User, error)
	FindAll(ctx context.Context, page, size int) ([]User, error)
	FindRoleByName(ctx context.Context, roleName string) (Role, error)
}
