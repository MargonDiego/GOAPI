package persistence

import (
	"context"
	"errors"

	"github.com/MargonDiego/GOAPI/internal/domain"
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
		Name:        role.Name,
		Description: role.Description,
		Scope:       role.Scope,
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
			perms = append(perms, domain.Permission{ID: dbPerm.ID, Name: dbPerm.Name, Description: dbPerm.Description})
		}
		roles = append(roles, domain.Role{
			ID:          dbRole.ID,
			Name:        dbRole.Name,
			Description: dbRole.Description,
			IsSystem:    dbRole.IsSystem,
			Scope:       dbRole.Scope,
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
		Description: dbRole.Description,
		IsSystem:    dbRole.IsSystem,
		Scope:       dbRole.Scope,
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

	// Actualizar campos editables.
	dbRole.Name = role.Name
	dbRole.Description = role.Description

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
		perms = append(perms, domain.Permission{ID: dbPerm.ID, Name: dbPerm.Name, Description: dbPerm.Description})
	}
	return perms, nil
}

// FindPermissionByName busca un permiso por su nombre exacto.
// Retorna domain.ErrPermissionNotFound si no existe.
func (r *roleRepository) FindPermissionByName(ctx context.Context, name string) (*domain.Permission, error) {
	var dbPerm Permission
	if err := r.db.WithContext(ctx).Where("name = ?", name).First(&dbPerm).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrPermissionNotFound
		}
		return nil, err
	}
	return &domain.Permission{ID: dbPerm.ID, Name: dbPerm.Name, Description: dbPerm.Description}, nil
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
		perms = append(perms, domain.Permission{ID: dbPerm.ID, Name: dbPerm.Name, Description: dbPerm.Description})
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
			perms = append(perms, domain.Permission{ID: dbPerm.ID, Name: dbPerm.Name, Description: dbPerm.Description})
		}
		roles = append(roles, domain.Role{
			ID:          dbRole.ID,
			Name:        dbRole.Name,
			Description: dbRole.Description,
			IsSystem:    dbRole.IsSystem,
			Scope:       dbRole.Scope,
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
		Description: dbRole.Description,
		IsSystem:    dbRole.IsSystem,
		Scope:       dbRole.Scope,
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

// CreatePermissionWithDescription inserta un permiso con nombre y descripción.
func (r *roleRepository) CreatePermissionWithDescription(ctx context.Context, name, description string) error {
	return r.db.WithContext(ctx).Create(&Permission{Name: name, Description: description}).Error
}

// UpdatePermission actualiza el nombre y descripción de un permiso existente.
func (r *roleRepository) UpdatePermission(ctx context.Context, perm *domain.Permission) error {
	return r.db.WithContext(ctx).Model(&Permission{}).Where("id = ?", perm.ID).Updates(map[string]any{
		"name":        perm.Name,
		"description": perm.Description,
	}).Error
}

// FindAllPaginated retorna una página de roles con permisos pre-cargados.
func (r *roleRepository) FindAllPaginated(ctx context.Context, page, size int) ([]domain.Role, error) {
	var dbRoles []Role
	offset := (page - 1) * size
	if err := r.db.WithContext(ctx).Preload("Permissions").Offset(offset).Limit(size).Find(&dbRoles).Error; err != nil {
		return nil, err
	}
	return toDomainRoles(dbRoles), nil
}

// SearchByName busca roles cuyo nombre contenga la query (case-insensitive).
func (r *roleRepository) SearchByName(ctx context.Context, query string) ([]domain.Role, error) {
	var dbRoles []Role
	if err := r.db.WithContext(ctx).Preload("Permissions").
		Where("name ILIKE ?", "%"+query+"%").Find(&dbRoles).Error; err != nil {
		return nil, err
	}
	return toDomainRoles(dbRoles), nil
}

// FindAllDeleted retorna todos los roles soft-deleted (incluyendo deleted_at).
func (r *roleRepository) FindAllDeleted(ctx context.Context) ([]domain.Role, error) {
	var dbRoles []Role
	if err := r.db.WithContext(ctx).Unscoped().Where("deleted_at IS NOT NULL").Find(&dbRoles).Error; err != nil {
		return nil, err
	}
	return toDomainRoles(dbRoles), nil
}

// Restore recupera un rol soft-deleted por su ID.
func (r *roleRepository) Restore(ctx context.Context, id uint) error {
	result := r.db.WithContext(ctx).Unscoped().Model(&Role{}).Where("id = ?", id).Update("deleted_at", nil)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return domain.ErrRoleNotFound
	}
	return nil
}

// FindAllPermissionsPaginated retorna una página de permisos.
func (r *roleRepository) FindAllPermissionsPaginated(ctx context.Context, page, size int) ([]domain.Permission, error) {
	var dbPerms []Permission
	offset := (page - 1) * size
	if err := r.db.WithContext(ctx).Offset(offset).Limit(size).Find(&dbPerms).Error; err != nil {
		return nil, err
	}
	return toDomainPermissions(dbPerms), nil
}

// FindAllPermissionsPaginatedWithTotal retorna permisos paginados con metadatos.
func (r *roleRepository) FindAllPermissionsPaginatedWithTotal(ctx context.Context, page, size int) (domain.PaginatedResult[domain.Permission], error) {
	var total int64
	if err := r.db.WithContext(ctx).Model(&Permission{}).Count(&total).Error; err != nil {
		return domain.PaginatedResult[domain.Permission]{}, err
	}

	perms, err := r.FindAllPermissionsPaginated(ctx, page, size)
	if err != nil {
		return domain.PaginatedResult[domain.Permission]{}, err
	}

	return domain.NewPaginatedResult(perms, page, size, int(total)), nil
}

// CountRoles retorna el total de roles activos.
func (r *roleRepository) CountRoles(ctx context.Context) (int64, error) {
	var count int64
	if err := r.db.WithContext(ctx).Model(&Role{}).Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

// CountRolesByScope retorna el total de roles activos filtrados por scope.
func (r *roleRepository) CountRolesByScope(ctx context.Context, scope string) (int64, error) {
	var count int64
	if err := r.db.WithContext(ctx).Model(&Role{}).Where("scope = ? OR scope = ''", scope).Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

// CountPermissions retorna el total de permisos activos.
func (r *roleRepository) CountPermissions(ctx context.Context) (int64, error) {
	var count int64
	if err := r.db.WithContext(ctx).Model(&Permission{}).Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

// FindAllByScope retorna roles filtrados por scope (incluyendo scope vacío).
func (r *roleRepository) FindAllByScope(ctx context.Context, scope string) ([]domain.Role, error) {
	var dbRoles []Role
	if err := r.db.WithContext(ctx).Preload("Permissions").
		Where("scope = ? OR scope = ''", scope).Find(&dbRoles).Error; err != nil {
		return nil, err
	}
	return toDomainRoles(dbRoles), nil
}

// FindAllPaginatedByScope retorna una página de roles filtrados por scope.
func (r *roleRepository) FindAllPaginatedByScope(ctx context.Context, scope string, page, size int) ([]domain.Role, error) {
	var dbRoles []Role
	offset := (page - 1) * size
	if err := r.db.WithContext(ctx).Preload("Permissions").
		Where("scope = ? OR scope = ''", scope).Offset(offset).Limit(size).Find(&dbRoles).Error; err != nil {
		return nil, err
	}
	return toDomainRoles(dbRoles), nil
}

// SearchByNameAndScope busca roles por nombre filtrados por scope.
func (r *roleRepository) SearchByNameAndScope(ctx context.Context, query, scope string) ([]domain.Role, error) {
	var dbRoles []Role
	if err := r.db.WithContext(ctx).Preload("Permissions").
		Where("(scope = ? OR scope = '') AND name ILIKE ?", scope, "%"+query+"%").Find(&dbRoles).Error; err != nil {
		return nil, err
	}
	return toDomainRoles(dbRoles), nil
}

// FindAllDeletedByScope retorna roles soft-deleted filtrados por scope.
func (r *roleRepository) FindAllDeletedByScope(ctx context.Context, scope string) ([]domain.Role, error) {
	var dbRoles []Role
	if err := r.db.WithContext(ctx).Unscoped().
		Where("deleted_at IS NOT NULL AND (scope = ? OR scope = '')", scope).Find(&dbRoles).Error; err != nil {
		return nil, err
	}
	return toDomainRoles(dbRoles), nil
}

// toDomainRoles convierte un slice de modelos DB a dominio.
func toDomainRoles(dbRoles []Role) []domain.Role {
	roles := make([]domain.Role, 0, len(dbRoles))
	for _, dbRole := range dbRoles {
		perms := make([]domain.Permission, 0, len(dbRole.Permissions))
		for _, dbPerm := range dbRole.Permissions {
			perms = append(perms, domain.Permission{ID: dbPerm.ID, Name: dbPerm.Name, Description: dbPerm.Description})
		}
		roles = append(roles, domain.Role{
			ID:          dbRole.ID,
			Name:        dbRole.Name,
			Description: dbRole.Description,
			IsSystem:    dbRole.IsSystem,
			Scope:       dbRole.Scope,
			Permissions: perms,
		})
	}
	return roles
}

// toDomainPermissions convierte un slice de permisos DB a dominio.
func toDomainPermissions(dbPerms []Permission) []domain.Permission {
	perms := make([]domain.Permission, 0, len(dbPerms))
	for _, dbPerm := range dbPerms {
		perms = append(perms, domain.Permission{ID: dbPerm.ID, Name: dbPerm.Name, Description: dbPerm.Description})
	}
	return perms
}
