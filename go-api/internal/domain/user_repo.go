package domain

import "context"

// UserRepository define el contrato de persistencia para la entidad User.
// La implementación concreta vive en infrastructure/persistence y usa GORM.
//
// NOTA: El método Save tiene comportamiento dual (INSERT si ID=0, UPDATE si ID>0).
// En una futura iteración se separará en Create y UpdateProfile para mayor claridad.
type UserRepository interface {
	// Save persiste un usuario nuevo (INSERT) o actualiza campos de perfil (UPDATE).
	Save(ctx context.Context, u *User) error

	// Update persiste campos de seguridad: intentos fallidos, bloqueo y email.
	Update(ctx context.Context, u *User) error

	// UpdateRoles reemplaza completamente los roles del usuario.
	UpdateRoles(ctx context.Context, userID uint, roles []Role) error

	// --- Queries ---
	FindByUsername(ctx context.Context, username string) (*User, error)
	FindByID(ctx context.Context, id uint) (*User, error)
	FindByEmailHash(ctx context.Context, emailHash string) (*User, error)
	FindAll(ctx context.Context, page, size int) ([]User, error)
	FindRoleByName(ctx context.Context, roleName string) (Role, error)

	// --- Token Version (invalidación de JWT) ---
	IncrementTokenVersion(ctx context.Context, userID uint) (int, error)
	GetTokenVersion(ctx context.Context, userID uint) (int, error)
	FindUserIDsByRoleID(ctx context.Context, roleID uint) ([]uint, error)

	// --- Refresh Tokens ---
	SaveRefreshToken(ctx context.Context, rt *RefreshToken) error
	GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error)
	DeleteRefreshToken(ctx context.Context, token string) error
	DeleteAllRefreshTokens(ctx context.Context, userID uint) error

	// --- Delete ---
	Delete(ctx context.Context, id uint) error
}
