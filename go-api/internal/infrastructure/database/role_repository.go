package database

import (
	"context"
	"errors"

	"github.com/diego/go-api/internal/domain"
	"gorm.io/gorm"
)

type roleRepository struct {
	db *gorm.DB
}

func NewRoleRepository(db *gorm.DB) domain.RoleRepository {
	return &roleRepository{db: db}
}

func (r *roleRepository) Create(ctx context.Context, role *domain.Role) error {
	dbRole := &Role{
		Name: role.Name,
	}
	if err := r.db.WithContext(ctx).Create(dbRole).Error; err != nil {
		return err
	}
	role.ID = dbRole.ID
	return nil
}

func (r *roleRepository) FindAll(ctx context.Context) ([]domain.Role, error) {
	var dbRoles []Role
	// Cargamos también los permisos de cada rol para que vengan en la respuesta
	if err := r.db.WithContext(ctx).Preload("Permissions").Find(&dbRoles).Error; err != nil {
		return nil, err
	}

	roles := make([]domain.Role, 0, len(dbRoles))
	for _, dbRole := range dbRoles {
		perms := make([]domain.Permission, 0, len(dbRole.Permissions))
		for _, dbPerm := range dbRole.Permissions {
			perms = append(perms, domain.Permission{ID: dbPerm.ID, Name: dbPerm.Name})
		}
		roles = append(roles, domain.Role{
			ID:          dbRole.ID,
			Name:        dbRole.Name,
			Permissions: perms,
		})
	}
	return roles, nil
}

func (r *roleRepository) FindByID(ctx context.Context, id uint) (*domain.Role, error) {
	var dbRole Role
	if err := r.db.WithContext(ctx).Preload("Permissions").First(&dbRole, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrRoleNotFound
		}
		return nil, err
	}

	perms := make([]domain.Permission, 0, len(dbRole.Permissions))
	for _, dbPerm := range dbRole.Permissions {
		perms = append(perms, domain.Permission{ID: dbPerm.ID, Name: dbPerm.Name})
	}

	return &domain.Role{
		ID:          dbRole.ID,
		Name:        dbRole.Name,
		Permissions: perms,
	}, nil
}

func (r *roleRepository) Update(ctx context.Context, role *domain.Role) error {
	// Buscamos el rol en DB
	var dbRole Role
	if err := r.db.WithContext(ctx).First(&dbRole, role.ID).Error; err != nil {
		return err
	}

	// Actualizamos campos simples
	dbRole.Name = role.Name

	// Sincronizamos la relación Many2Many de Permisos
	var dbPerms []Permission
	for _, p := range role.Permissions {
		dbPerms = append(dbPerms, Permission{Model: gorm.Model{ID: p.ID}, Name: p.Name})
	}

	// Esto reemplaza completamente las relaciones actuales por las nuevas
	if err := r.db.WithContext(ctx).Model(&dbRole).Association("Permissions").Replace(&dbPerms); err != nil {
		return err
	}

	// Guardamos el rol en sí mismo
	return r.db.WithContext(ctx).Save(&dbRole).Error
}

func (r *roleRepository) FindAllPermissions(ctx context.Context) ([]domain.Permission, error) {
	var dbPerms []Permission
	if err := r.db.WithContext(ctx).Find(&dbPerms).Error; err != nil {
		return nil, err
	}

	perms := make([]domain.Permission, 0, len(dbPerms))
	for _, dbPerm := range dbPerms {
		perms = append(perms, domain.Permission{ID: dbPerm.ID, Name: dbPerm.Name})
	}
	return perms, nil
}

func (r *roleRepository) FindPermissionsByIDs(ctx context.Context, ids []uint) ([]domain.Permission, error) {
	var dbPerms []Permission
	if err := r.db.WithContext(ctx).Where("id IN ?", ids).Find(&dbPerms).Error; err != nil {
		return nil, err
	}

	perms := make([]domain.Permission, 0, len(dbPerms))
	for _, dbPerm := range dbPerms {
		perms = append(perms, domain.Permission{ID: dbPerm.ID, Name: dbPerm.Name})
	}
	return perms, nil
}

func (r *roleRepository) FindRolesByIDs(ctx context.Context, ids []uint) ([]domain.Role, error) {
	var dbRoles []Role
	if err := r.db.WithContext(ctx).Preload("Permissions").Where("id IN ?", ids).Find(&dbRoles).Error; err != nil {
		return nil, err
	}

	roles := make([]domain.Role, 0, len(dbRoles))
	for _, dbRole := range dbRoles {
		perms := make([]domain.Permission, 0, len(dbRole.Permissions))
		for _, dbPerm := range dbRole.Permissions {
			perms = append(perms, domain.Permission{ID: dbPerm.ID, Name: dbPerm.Name})
		}
		roles = append(roles, domain.Role{
			ID:          dbRole.ID,
			Name:        dbRole.Name,
			Permissions: perms,
		})
	}
	return roles, nil
}
