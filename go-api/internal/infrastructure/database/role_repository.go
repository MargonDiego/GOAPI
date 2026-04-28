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

// NewRoleRepository construye un roleRepository con la conexión GORM inyectada.
func NewRoleRepository(db *gorm.DB) domain.RoleRepository {
	return &roleRepository{db: db}
}

// Create inserta un nuevo rol en la base de datos y propaga el ID generado al objeto de dominio.
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

// FindAll retorna todos los roles del sistema con sus permisos pre-cargados.
func (r *roleRepository) FindAll(ctx context.Context) ([]domain.Role, error) {
	var dbRoles []Role
	// Preload de Permissions para que cada rol incluya sus permisos en la respuesta.
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

// FindByID retorna un rol por su ID primario con sus permisos pre-cargados.
// Retorna domain.ErrRoleNotFound si no existe ningún rol con ese ID.
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

// Update persiste el nuevo nombre del rol y reemplaza completamente su relación
// Many-to-Many con permisos. El reemplazo es atómico desde el punto de vista del caller.
func (r *roleRepository) Update(ctx context.Context, role *domain.Role) error {
	var dbRole Role
	if err := r.db.WithContext(ctx).First(&dbRole, role.ID).Error; err != nil {
		return err
	}

	// Actualizar el campo de nombre.
	dbRole.Name = role.Name

	// Construir la lista de permisos a asociar (solo ID necesario para la join table).
	var dbPerms []Permission
	for _, p := range role.Permissions {
		dbPerms = append(dbPerms, Permission{Model: gorm.Model{ID: p.ID}, Name: p.Name})
	}

	// Replace reemplaza completamente las relaciones actuales por las nuevas.
	if err := r.db.WithContext(ctx).Model(&dbRole).Association("Permissions").Replace(&dbPerms); err != nil {
		return err
	}

	return r.db.WithContext(ctx).Save(&dbRole).Error
}

// FindAllPermissions retorna todos los permisos disponibles en el sistema.
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

// FindPermissionsByIDs retorna los permisos cuyos IDs están en el slice dado.
// Si algún ID no existe, el resultado tendrá menos elementos que el input —
// el caller debe validar que len(result) == len(ids) si necesita exactitud.
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

// FindRolesByIDs retorna los roles cuyos IDs están en el slice dado, con permisos pre-cargados.
// Si algún ID no existe, el resultado tendrá menos elementos que el input —
// el caller debe validar que len(result) == len(ids) si necesita exactitud.
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

// FindByName busca un rol por nombre exacto con sus permisos pre-cargados.
// Retorna domain.ErrRoleNotFound si no existe ningún rol con ese nombre.
func (r *roleRepository) FindByName(ctx context.Context, name string) (*domain.Role, error) {
	var dbRole Role
	if err := r.db.WithContext(ctx).Preload("Permissions").Where("name = ?", name).First(&dbRole).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrRoleNotFound
		}
		return nil, err
	}

	perms := make([]domain.Permission, 0, len(dbRole.Permissions))
	for _, p := range dbRole.Permissions {
		perms = append(perms, domain.Permission{ID: p.ID, Name: p.Name})
	}

	return &domain.Role{
		ID:          dbRole.ID,
		Name:        dbRole.Name,
		Permissions: perms,
	}, nil
}

// Delete elimina permanentemente un rol por ID.
// Los registros en la tabla join role_permissions se eliminan en cascada por GORM.
// Retorna domain.ErrRoleNotFound si no existe ningún rol con ese ID.
func (r *roleRepository) Delete(ctx context.Context, id uint) error {
	result := r.db.WithContext(ctx).Delete(&Role{}, id)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return domain.ErrRoleNotFound
	}
	return nil
}

// CreatePermission inserta un nuevo permiso con el nombre dado.
func (r *roleRepository) CreatePermission(ctx context.Context, name string) error {
	return r.db.WithContext(ctx).Create(&Permission{Name: name}).Error
}
