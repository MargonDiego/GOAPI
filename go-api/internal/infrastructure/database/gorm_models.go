package database

import (
	"github.com/diego/go-api/internal/domain"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username string `gorm:"uniqueIndex;not null"`
	Password string `gorm:"not null"`
	Roles    []Role `gorm:"many2many:user_roles;"`
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

func toDomainUser(u *User) *domain.User {
	if u == nil {
		return nil
	}
	du := &domain.User{
		ID:           u.ID,
		Username:     u.Username,
		PasswordHash: u.Password,
		Roles:        make([]domain.Role, 0, len(u.Roles)), // Pre-alocación optimizada
	}

	for _, r := range u.Roles {
		dr := domain.Role{
			ID:          r.ID,
			Name:        r.Name,
			Permissions: make([]domain.Permission, 0, len(r.Permissions)), // Pre-alocación optimizada
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
		Username: du.Username,
		Password: du.PasswordHash,
		Roles:    make([]Role, 0, len(du.Roles)),
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
