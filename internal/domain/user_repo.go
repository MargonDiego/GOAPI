package domain

import "context"

// --- Interfaces segregadas (Principio de SegregaciÃ³n de Interfaces) ---
//
// UserRepository se descompone en tres contratos especializados.
// Los consumidores que solo necesitan lectura (ej: AuthMiddleware) pueden
// depender de UserReader en lugar del repositorio completo.
//
// La interfaz compuesta UserRepository se mantiene por retrocompatibilidad
// y para el wiring en main.go donde se necesita el contrato completo.

// UserReader agrupa las operaciones de consulta sobre usuarios.
type UserReader interface {
	FindByUsername(ctx context.Context, username string) (*User, error)
	FindByID(ctx context.Context, id uint) (*User, error)
	FindByEmailHash(ctx context.Context, emailHash string) (*User, error)
	FindAll(ctx context.Context, page, size int) ([]User, error)
	FindAllByScope(ctx context.Context, scope string, page, size int) ([]User, error)
	SearchUsers(ctx context.Context, query string, roleName string, page, size int) ([]User, error)
	SearchUsersByScope(ctx context.Context, query, roleName, scope string, page, size int) ([]User, error)
	FindAllDeleted(ctx context.Context) ([]User, error)
	FindAllDeletedByScope(ctx context.Context, scope string) ([]User, error)

	// Token version queries
	GetTokenVersion(ctx context.Context, userID uint) (int, error)
	FindUserIDsByRoleID(ctx context.Context, roleID uint) ([]uint, error)

	// Contadores para metadatos de paginaciÃ³n
	CountUsers(ctx context.Context) (int64, error)
	CountUsersByScope(ctx context.Context, scope string) (int64, error)
	CountSearchUsers(ctx context.Context, query, roleName string) (int64, error)
	CountSearchUsersByScope(ctx context.Context, query, roleName, scope string) (int64, error)
}

// UserWriter agrupa las operaciones de mutaciÃ³n sobre usuarios.
type UserWriter interface {
	Create(ctx context.Context, u *User) error
	UpdateProfile(ctx context.Context, u *User) error
	Update(ctx context.Context, u *User) error
	UpdateRoles(ctx context.Context, userID uint, roles []Role) error
	IncrementTokenVersion(ctx context.Context, userID uint) (int, error)
	Delete(ctx context.Context, id uint) error
	Restore(ctx context.Context, id uint) error
}

// TokenStore agrupa las operaciones de persistencia de Refresh Tokens.
type TokenStore interface {
	SaveRefreshToken(ctx context.Context, rt *RefreshToken) error
	GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error)
	DeleteRefreshToken(ctx context.Context, token string) error
	DeleteAllRefreshTokens(ctx context.Context, userID uint) error
}

// UserRepository es la interfaz compuesta que agrupa los tres contratos.
// Es la dependencia principal para servicios que necesitan acceso completo
// a usuarios y tokens (AuthService, UserService).
type UserRepository interface {
	UserReader
	UserWriter
	TokenStore
}
