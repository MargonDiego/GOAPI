package application

import (
	"context"
	"errors"
	"fmt"

	"github.com/diego/go-api/internal/domain"
	"github.com/diego/go-api/internal/infrastructure/cache"
	appcrypto "github.com/diego/go-api/internal/infrastructure/crypto"
)

// UserService define el contrato de la capa de aplicación para operaciones sobre usuarios.
// Toda la lógica de negocio (validaciones, orquestación de repositorios, hash de passwords)
// vive aquí, manteniendo los handlers libres de reglas de dominio.
type UserService interface {
	// GetUserByUsername busca un usuario por su nombre de usuario único.
	// Retorna domain.ErrUserNotFound si no existe.
	GetUserByUsername(ctx context.Context, username string) (*domain.User, error)

	// GetAllUsers retorna una página de usuarios ordenados por ID ascendente.
	// page empieza en 1; size se normaliza al rango [1, 100].
	GetAllUsers(ctx context.Context, page, size int) ([]domain.User, error)

	// GetUserByID busca un usuario por su ID primario.
	// Retorna domain.ErrUserNotFound si no existe.
	GetUserByID(ctx context.Context, id uint) (*domain.User, error)

	// CreateUser crea un nuevo usuario aplicando todas las invariantes del dominio:
	// unicidad de username y email, hash de password y asignación del rol por defecto "User".
	// Retorna domain.ErrUserAlreadyExists o domain.ErrEmailAlreadyExists si ya están en uso.
	CreateUser(ctx context.Context, username, password, email string) error

	// UpdateUser actualiza el username y/o email de un usuario existente (patch semántico).
	// Los campos vacíos se ignoran. Si se provee email, se verifica unicidad y se re-cifra.
	// Retorna domain.ErrUserNotFound si el usuario no existe,
	// domain.ErrEmailAlreadyExists si el email ya pertenece a otro usuario.
	UpdateUser(ctx context.Context, userID uint, username, email string) error

	// DeleteUser elimina permanentemente un usuario del sistema.
	// Retorna domain.ErrUserNotFound si el usuario no existe.
	DeleteUser(ctx context.Context, userID uint) error

	// AssignRolesToUser reemplaza completamente los roles de un usuario.
	// Pasar un slice vacío elimina todos sus roles.
	// Retorna domain.ErrInvalidInput si algún roleID no existe en la base de datos.
	AssignRolesToUser(ctx context.Context, userID uint, roleIDs []uint) error
}

type userService struct {
	repo         domain.UserRepository
	roleRepo     domain.RoleRepository
	enc          *appcrypto.Encryptor
	versionCache *cache.TokenVersionCache // nil-safe: si no se inyecta, la invalidación espera al TTL
}

// NewUserService construye un UserService con todas sus dependencias inyectadas.
// versionCache puede ser nil (el sistema funciona correctamente, con TTL de 30s como ventana).
func NewUserService(repo domain.UserRepository, roleRepo domain.RoleRepository, enc *appcrypto.Encryptor, versionCache *cache.TokenVersionCache) UserService {
	return &userService{repo: repo, roleRepo: roleRepo, enc: enc, versionCache: versionCache}
}

// GetUserByUsername busca al usuario por username. Propaga ErrUserNotFound del repositorio.
func (s *userService) GetUserByUsername(ctx context.Context, username string) (*domain.User, error) {
	user, err := s.repo.FindByUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("failed to get user by username: %w", err)
	}
	return user, nil
}

// GetAllUsers normaliza la paginación y delega al repositorio.
// page < 1 se corrige a 1; size fuera de (0, 100] se corrige a 10.
func (s *userService) GetAllUsers(ctx context.Context, page, size int) ([]domain.User, error) {
	if page < 1 {
		page = 1
	}
	if size <= 0 || size > 100 {
		size = 10
	}

	users, err := s.repo.FindAll(ctx, page, size)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	return users, nil
}

// AssignRolesToUser valida la existencia del usuario y de cada role antes de aplicar el reemplazo.
// Pasar roleIDs vacío es válido y elimina todos los roles del usuario.
// Tras actualizar los roles incrementa token_version para invalidar los JWT activos del usuario.
func (s *userService) AssignRolesToUser(ctx context.Context, userID uint, roleIDs []uint) error {
	// Verificar existencia del usuario antes de operar.
	_, err := s.repo.FindByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to find user: %w", err)
	}

	// Resolver y validar los roles solicitados.
	var roles []domain.Role
	if len(roleIDs) > 0 {
		roles, err = s.roleRepo.FindRolesByIDs(ctx, roleIDs)
		if err != nil {
			return fmt.Errorf("failed to retrieve roles: %w", err)
		}
		if len(roles) != len(roleIDs) {
			return fmt.Errorf("%w: some roles were not found", domain.ErrInvalidInput)
		}
	}

	if err := s.repo.UpdateRoles(ctx, userID, roles); err != nil {
		return fmt.Errorf("failed to update user roles: %w", err)
	}

	// Invalidar los JWT activos del usuario incrementando su token_version.
	// A partir de este momento, cualquier request con el token anterior recibirá 401.
	// El cache en el middleware se invalida explícitamente para que el efecto sea inmediato
	// (en lugar de esperar el TTL de 30s del cache).
	if _, err := s.repo.IncrementTokenVersion(ctx, userID); err != nil {
		return fmt.Errorf("failed to invalidate user tokens: %w", err)
	}
	if s.versionCache != nil {
		s.versionCache.Invalidate(userID)
	}

	return nil
}

// GetUserByID retorna el usuario con sus roles y permisos cargados.
// Propaga ErrUserNotFound si el ID no existe.
func (s *userService) GetUserByID(ctx context.Context, id uint) (*domain.User, error) {
	user, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return user, nil
}

// CreateUser verifica unicidad de username y email, hashea la contraseña,
// asigna el rol por defecto "User" y persiste el nuevo usuario.
func (s *userService) CreateUser(ctx context.Context, username, password, email string) error {
	_, err := s.repo.FindByUsername(ctx, username)
	if err == nil {
		return fmt.Errorf("%w: username already exists", domain.ErrUserAlreadyExists)
	}
	if !errors.Is(err, domain.ErrUserNotFound) {
		return fmt.Errorf("failed to check username: %w", err)
	}

	emailHash := ""
	if email != "" {
		emailHash = s.enc.HashEmail(email)
		_, err := s.repo.FindByEmailHash(ctx, emailHash)
		if err == nil {
			return fmt.Errorf("%w: email already exists", domain.ErrEmailAlreadyExists)
		}
		if !errors.Is(err, domain.ErrUserNotFound) {
			return fmt.Errorf("failed to check email: %w", err)
		}
	}

	defaultRole, err := s.roleRepo.FindByName(ctx, "User")
	if err != nil {
		return fmt.Errorf("failed to get default role: %w", err)
	}

	user, err := domain.NewUser(username, password, *defaultRole)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	// Persistir el email cifrado solo si fue provisto.
	if email != "" {
		encryptedEmail, err := s.enc.EncryptEmail(email)
		if err != nil {
			return fmt.Errorf("failed to encrypt email: %w", err)
		}
		user.EmailEncrypted = encryptedEmail
		user.EmailHash = emailHash
	}

	if err := s.repo.Save(ctx, user); err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// UpdateUser aplica un patch sobre username y/o email de un usuario existente.
// Si se provee email, se verifica unicidad contra otros usuarios y se re-cifra con AES-256-GCM.
// Internamente llama a repo.Save que detecta el ID > 0 y ejecuta un UPDATE (no INSERT).
func (s *userService) UpdateUser(ctx context.Context, userID uint, username, email string) error {
	user, err := s.repo.FindByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to find user: %w", err)
	}

	if username != "" {
		user.Username = username
	}

	if email != "" {
		emailHash := s.enc.HashEmail(email)
		// Solo re-validar unicidad si el email realmente cambió.
		if emailHash != user.EmailHash {
			_, err := s.repo.FindByEmailHash(ctx, emailHash)
			if err == nil {
				return fmt.Errorf("%w: email already in use", domain.ErrEmailAlreadyExists)
			}
			if !errors.Is(err, domain.ErrUserNotFound) {
				return fmt.Errorf("failed to check email uniqueness: %w", err)
			}
			encryptedEmail, err := s.enc.EncryptEmail(email)
			if err != nil {
				return fmt.Errorf("failed to encrypt email: %w", err)
			}
			user.EmailEncrypted = encryptedEmail
			user.EmailHash = emailHash
		}
	}

	// repo.Save detecta ID > 0 y ejecuta UPDATE en lugar de INSERT.
	if err := s.repo.Save(ctx, user); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

// DeleteUser elimina el usuario. Propaga ErrUserNotFound si el ID no existe.
func (s *userService) DeleteUser(ctx context.Context, userID uint) error {
	if err := s.repo.Delete(ctx, userID); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	return nil
}
