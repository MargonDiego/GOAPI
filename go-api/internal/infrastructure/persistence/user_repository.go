package persistence

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

// NewUserRepository construye un userRepository con la conexión GORM inyectada.
func NewUserRepository(db *gorm.DB) domain.UserRepository {
	return &userRepository{db: db}
}

// Create inserta un nuevo usuario y propaga el ID generado al objeto de dominio.
// Pensado exclusivamente para INSERTS — si el usuario ya tiene ID, se ignora (GORM trata ID>0 como update).
func (r *userRepository) Create(ctx context.Context, u *domain.User) error {
	dbUser := toDBUser(u)
	if err := r.db.WithContext(ctx).Create(dbUser).Error; err != nil {
		return fmt.Errorf("repository unable to create user: %w", err)
	}
	u.ID = dbUser.ID
	return nil
}

// UpdateProfile actualiza selectivamente los campos de perfil (username, email) de un usuario existente.
// Usa Select explícito para evitar sobrescribir password, failed_attempts y campos de seguridad.
func (r *userRepository) UpdateProfile(ctx context.Context, u *domain.User) error {
	dbUser := toDBUser(u)
	if err := r.db.WithContext(ctx).
		Model(dbUser).
		Select("username", "email_encrypted", "email_hash").
		Updates(dbUser).Error; err != nil {
		return fmt.Errorf("repository unable to update profile: %w", err)
	}
	return nil
}

// Update persiste los campos de seguridad de un usuario existente: intentos fallidos,
// bloqueo de cuenta y email cifrado/hasheado.
// Usamos Select explícito para evitar sobrescribir campos sensibles por accidente
// (ej: un update de intentos fallidos no debe borrar el password ni el username).
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

// UpdateRoles reemplaza completamente la relación Many-to-Many usuario↔roles.
// Pasar un slice vacío elimina todos los roles del usuario.
// Retorna domain.ErrUserNotFound si el usuario no existe.
func (r *userRepository) UpdateRoles(ctx context.Context, userID uint, roles []domain.Role) error {
	var dbUser User
	if err := r.db.WithContext(ctx).First(&dbUser, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return domain.ErrUserNotFound
		}
		return err
	}

	var dbRoles []Role
	for _, role := range roles {
		dbRoles = append(dbRoles, Role{Model: gorm.Model{ID: role.ID}, Name: role.Name})
	}

	return r.db.WithContext(ctx).Model(&dbUser).Association("Roles").Replace(&dbRoles)
}

// FindByUsername retorna el usuario con sus roles y permisos pre-cargados.
// Retorna domain.ErrUserNotFound si no existe ningún usuario con ese username.
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

// FindByEmailHash busca un usuario por el HMAC-SHA256 de su email.
// Se usa para verificar unicidad de email sin exponer datos en claro.
// Retorna domain.ErrUserNotFound si no existe ningún usuario con ese hash.
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

// FindByID retorna el usuario con sus roles y permisos pre-cargados.
// Retorna domain.ErrUserNotFound si no existe ningún usuario con ese ID.
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

// FindAll retorna una página de usuarios con roles y permisos pre-cargados.
// page empieza en 1; el offset se calcula como (page-1)*size.
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

// FindRoleByName busca un rol por nombre exacto con sus permisos pre-cargados.
// Retorna domain.ErrRoleNotFound si no existe.
// IncrementTokenVersion incrementa en 1 el token_version del usuario y retorna el nuevo valor.
// Debe llamarse siempre que cambien los roles o permisos de un usuario para invalidar
// sus JWT activos. La operación es atómica a nivel de base de datos.
func (r *userRepository) IncrementTokenVersion(ctx context.Context, userID uint) (int, error) {
	result := r.db.WithContext(ctx).
		Model(&User{}).
		Where("id = ?", userID).
		UpdateColumn("token_version", gorm.Expr("token_version + 1"))

	if result.Error != nil {
		return 0, fmt.Errorf("failed to increment token version: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return 0, domain.ErrUserNotFound
	}

	// Re-leer el valor actualizado para retornarlo.
	var u User
	if err := r.db.WithContext(ctx).Select("token_version").First(&u, userID).Error; err != nil {
		return 0, fmt.Errorf("failed to read updated token version: %w", err)
	}
	return u.TokenVersion, nil
}

// GetTokenVersion retorna el token_version actual del usuario.
// Usado por el middleware para validar el claim "ver" del JWT.
// Retorna domain.ErrUserNotFound si el usuario no existe.
func (r *userRepository) GetTokenVersion(ctx context.Context, userID uint) (int, error) {
	var u User
	if err := r.db.WithContext(ctx).Select("token_version").First(&u, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return 0, domain.ErrUserNotFound
		}
		return 0, fmt.Errorf("failed to get token version: %w", err)
	}
	return u.TokenVersion, nil
}

// FindUserIDsByRoleID retorna los IDs de todos los usuarios que tienen asignado el rol indicado.
// Consulta directamente la tabla join user_roles para evitar cargar los objetos completos.
func (r *userRepository) FindUserIDsByRoleID(ctx context.Context, roleID uint) ([]uint, error) {
	type userRole struct {
		UserID uint
	}
	var rows []userRole
	if err := r.db.WithContext(ctx).
		Table("user_roles").
		Where("role_id = ?", roleID).
		Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("failed to query users by role: %w", err)
	}

	ids := make([]uint, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.UserID)
	}
	return ids, nil
}

// SaveRefreshToken persiste un nuevo refresh token asociado al usuario.
func (r *userRepository) SaveRefreshToken(ctx context.Context, rt *domain.RefreshToken) error {
	dbRT := &RefreshToken{
		UserID:    rt.UserID,
		Token:     rt.Token,
		ExpiresAt: rt.ExpiresAt,
	}
	return r.db.WithContext(ctx).Create(dbRT).Error
}

// GetRefreshToken busca un refresh token por su valor.
// Retorna domain.ErrInvalidToken si no existe o ya fue consumido/expirado.
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

// DeleteRefreshToken elimina un refresh token específico (logout de una sesión).
func (r *userRepository) DeleteRefreshToken(ctx context.Context, token string) error {
	return r.db.WithContext(ctx).Where("token = ?", token).Delete(&RefreshToken{}).Error
}

// DeleteAllRefreshTokens invalida todos los refresh tokens de un usuario (logout global).
func (r *userRepository) DeleteAllRefreshTokens(ctx context.Context, userID uint) error {
	return r.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&RefreshToken{}).Error
}

// Delete elimina permanentemente un usuario por ID (hard delete).
// Retorna domain.ErrUserNotFound si el usuario no existe.
func (r *userRepository) Delete(ctx context.Context, id uint) error {
	result := r.db.WithContext(ctx).Delete(&User{}, id)
	if result.Error != nil {
		return fmt.Errorf("repository unable to delete user: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}

// SearchUsers busca usuarios por username/email y filtra por nombre de rol.
// La búsqueda es case-insensitive en username. Si query está vacío, lista todos.
// Si roleName está vacío, no filtra por rol.
func (r *userRepository) SearchUsers(ctx context.Context, query, roleName string, page, size int) ([]domain.User, error) {
	var users []User
	db := r.db.WithContext(ctx).Preload("Roles.Permissions")

	if query != "" {
		db = db.Where("username ILIKE ? OR email_hash ILIKE ?", "%"+query+"%", "%"+query+"%")
	}

	if roleName != "" {
		db = db.Joins("JOIN user_roles ON user_roles.user_id = users.id").
			Joins("JOIN roles ON roles.id = user_roles.role_id").
			Where("roles.name = ?", roleName)
	}

	offset := (page - 1) * size
	if err := db.Offset(offset).Limit(size).Find(&users).Error; err != nil {
		return nil, fmt.Errorf("database search user error: %w", err)
	}

	var dUsers []domain.User
	for _, u := range users {
		dUsers = append(dUsers, *toDomainUser(&u))
	}
	return dUsers, nil
}

// SearchUsersByScope busca usuarios filtrados por scope del actor.
func (r *userRepository) SearchUsersByScope(ctx context.Context, query, roleName, scope string, page, size int) ([]domain.User, error) {
	var users []User
	db := r.db.WithContext(ctx).Preload("Roles.Permissions").
		Where("users.scope = ? OR users.scope = ''", scope)

	if query != "" {
		db = db.Where("username ILIKE ? OR email_hash ILIKE ?", "%"+query+"%", "%"+query+"%")
	}

	if roleName != "" {
		db = db.Joins("JOIN user_roles ON user_roles.user_id = users.id").
			Joins("JOIN roles ON roles.id = user_roles.role_id").
			Where("roles.name = ?", roleName)
	}

	offset := (page - 1) * size
	if err := db.Offset(offset).Limit(size).Find(&users).Error; err != nil {
		return nil, fmt.Errorf("database search user by scope error: %w", err)
	}

	var dUsers []domain.User
	for _, u := range users {
		dUsers = append(dUsers, *toDomainUser(&u))
	}
	return dUsers, nil
}

// FindAllByScope retorna usuarios paginados filtrados por scope.
func (r *userRepository) FindAllByScope(ctx context.Context, scope string, page, size int) ([]domain.User, error) {
	var users []User
	offset := (page - 1) * size

	if err := r.db.WithContext(ctx).Preload("Roles.Permissions").
		Where("scope = ? OR scope = ''", scope).Offset(offset).Limit(size).Find(&users).Error; err != nil {
		return nil, fmt.Errorf("database list user by scope error: %w", err)
	}

	var dUsers []domain.User
	for _, u := range users {
		dUsers = append(dUsers, *toDomainUser(&u))
	}
	return dUsers, nil
}

// CountUsers retorna el total de usuarios activos.
func (r *userRepository) CountUsers(ctx context.Context) (int64, error) {
	var count int64
	if err := r.db.WithContext(ctx).Model(&User{}).Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

// CountUsersByScope retorna el total de usuarios activos filtrados por scope.
func (r *userRepository) CountUsersByScope(ctx context.Context, scope string) (int64, error) {
	var count int64
	if err := r.db.WithContext(ctx).Model(&User{}).Where("scope = ? OR scope = ''", scope).Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

// CountSearchUsers retorna el total de usuarios que coinciden con los criterios de búsqueda.
func (r *userRepository) CountSearchUsers(ctx context.Context, query, roleName string) (int64, error) {
	db := r.db.WithContext(ctx).Model(&User{})

	if query != "" {
		db = db.Where("username ILIKE ? OR email_hash ILIKE ?", "%"+query+"%", "%"+query+"%")
	}

	if roleName != "" {
		db = db.Joins("JOIN user_roles ON user_roles.user_id = users.id").
			Joins("JOIN roles ON roles.id = user_roles.role_id").
			Where("roles.name = ?", roleName)
	}

	var count int64
	if err := db.Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

// CountSearchUsersByScope retorna el total de usuarios que coinciden con los criterios de búsqueda filtrados por scope.
func (r *userRepository) CountSearchUsersByScope(ctx context.Context, query, roleName, scope string) (int64, error) {
	db := r.db.WithContext(ctx).Model(&User{}).Where("users.scope = ? OR users.scope = ''", scope)

	if query != "" {
		db = db.Where("username ILIKE ? OR email_hash ILIKE ?", "%"+query+"%", "%"+query+"%")
	}

	if roleName != "" {
		db = db.Joins("JOIN user_roles ON user_roles.user_id = users.id").
			Joins("JOIN roles ON roles.id = user_roles.role_id").
			Where("roles.name = ?", roleName)
	}

	var count int64
	if err := db.Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

// FindAllDeleted retorna todos los usuarios soft-deleted.
func (r *userRepository) FindAllDeleted(ctx context.Context) ([]domain.User, error) {
	var users []User
	if err := r.db.WithContext(ctx).Unscoped().Where("deleted_at IS NOT NULL").Preload("Roles.Permissions").Find(&users).Error; err != nil {
		return nil, fmt.Errorf("database list deleted users error: %w", err)
	}

	var dUsers []domain.User
	for _, u := range users {
		dUsers = append(dUsers, *toDomainUser(&u))
	}
	return dUsers, nil
}

// FindAllDeletedByScope retorna usuarios soft-deleted filtrados por scope.
func (r *userRepository) FindAllDeletedByScope(ctx context.Context, scope string) ([]domain.User, error) {
	var users []User
	if err := r.db.WithContext(ctx).Unscoped().
		Where("deleted_at IS NOT NULL AND (scope = ? OR scope = '')", scope).Preload("Roles.Permissions").Find(&users).Error; err != nil {
		return nil, fmt.Errorf("database list deleted users by scope error: %w", err)
	}

	var dUsers []domain.User
	for _, u := range users {
		dUsers = append(dUsers, *toDomainUser(&u))
	}
	return dUsers, nil
}

// Restore recupera un usuario soft-deleted por su ID.
func (r *userRepository) Restore(ctx context.Context, id uint) error {
	result := r.db.WithContext(ctx).Unscoped().Model(&User{}).Where("id = ?", id).Update("deleted_at", nil)
	if result.Error != nil {
		return fmt.Errorf("repository unable to restore user: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}
