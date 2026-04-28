package application

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/diego/go-api/internal/domain"
	appcrypto "github.com/diego/go-api/internal/infrastructure/crypto"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// AuthService define el contrato de la capa de aplicación para el ciclo de vida
// de autenticación: registro, login, renovación de tokens y cierre de sesión.
//
// Todas las operaciones son context-aware y propagan timeouts hacia la capa de
// infraestructura para evitar bloqueos ante latencia de red o base de datos.
type AuthService interface {
	// Register crea un nuevo usuario con el rol "User" por defecto.
	// Valida unicidad de username y email antes de persistir.
	// El email se almacena cifrado (AES-256-GCM) y su hash (HMAC-SHA256) se usa
	// para búsquedas sin exponer datos en claro.
	Register(ctx context.Context, username, password, email string) error

	// Login autentica las credenciales del usuario y emite un par de tokens:
	// un Access Token (Fat JWT, TTL 15 min) y un Refresh Token (TTL 7 días).
	// Aplica account lockout: tras el máximo de intentos fallidos configurado en
	// domain.MaxFailedAttempts, la cuenta queda bloqueada hasta que expire el
	// período domain.LockDuration.
	Login(ctx context.Context, username, password string) (accessToken string, refreshToken string, err error)

	// RefreshTokens implementa rotación estricta de tokens: invalida el Refresh Token
	// recibido y emite un par nuevo. El nuevo Access Token refleja la token_version
	// actual del usuario, incorporando cualquier cambio de roles ocurrido desde el
	// login original.
	RefreshTokens(ctx context.Context, refreshToken string) (accessToken string, newRefreshToken string, err error)

	// Logout invalida todos los Refresh Tokens activos del usuario, forzando
	// re-autenticación en todos los dispositivos. Los Access Tokens en circulación
	// expiran por TTL natural (máx. 15 min).
	Logout(ctx context.Context, userID uint) error
}

// authService es la implementación concreta de AuthService.
// Orquesta el repositorio de usuarios, la firma JWT y el cifrado de emails.
type authService struct {
	repo      domain.UserRepository
	jwtSecret []byte
	enc       *appcrypto.Encryptor
}

// NewAuthService construye un authService con todas sus dependencias inyectadas.
//   - repo: repositorio de usuarios (acceso a Postgres vía GORM).
//   - secret: clave HMAC-SHA256 para firmar y verificar JWTs; debe tener ≥ 64 bytes.
//   - enc: encriptador AES-256-GCM para cifrar emails y calcular su hash de búsqueda.
func NewAuthService(repo domain.UserRepository, secret []byte, enc *appcrypto.Encryptor) AuthService {
	return &authService{repo: repo, jwtSecret: secret, enc: enc}
}

// Register implementa AuthService.Register.
//
// Flujo de seguridad:
//  1. Valida longitud de contraseña (8-72 chars) para evitar CPU starvation pre-bcrypt.
//  2. Verifica unicidad de username vía consulta directa.
//  3. Si se proveyó email, verifica unicidad por HMAC-SHA256 sin exponer el valor en claro.
//  4. Cifra el email con AES-256-GCM antes de persistirlo.
//  5. Hashea la contraseña con bcrypt (DefaultCost).
//  6. Asigna el rol "User" por defecto al nuevo usuario.
//
// Errores posibles: domain.ErrInvalidInput, domain.ErrUserAlreadyExists,
// domain.ErrEmailAlreadyExists.
func (s *authService) Register(ctx context.Context, username, password, email string) error {
	if len(password) < 8 || len(password) > 72 {
		return fmt.Errorf("%w: password length must be 8-72 characters", domain.ErrInvalidInput)
	}
	if email == "" {
		return fmt.Errorf("%w: email is required", domain.ErrInvalidInput)
	}

	ctxTimeout, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	_, err := s.repo.FindByUsername(ctxTimeout, username)
	if err == nil {
		return domain.ErrUserAlreadyExists
	}
	if !errors.Is(err, domain.ErrUserNotFound) {
		return fmt.Errorf("unexpected database error checking username: %w", err)
	}

	// Si el usuario proveyó email, verificar duplicado por hash antes de cifrar.
	var emailEncrypted, emailHash string
	if email != "" {
		emailHash = s.enc.HashEmail(email)

		_, err := s.repo.FindByEmailHash(ctxTimeout, emailHash)
		if err == nil {
			return domain.ErrEmailAlreadyExists
		}
		if !errors.Is(err, domain.ErrUserNotFound) {
			return fmt.Errorf("unexpected database error checking email: %w", err)
		}

		emailEncrypted, err = s.enc.EncryptEmail(email)
		if err != nil {
			return fmt.Errorf("email encryption failure: %w", err)
		}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("crypto hashing failure: %w", err)
	}

	defaultRole, err := s.repo.FindRoleByName(ctxTimeout, "User")
	if err != nil {
		return fmt.Errorf("could not retrieve default role: %w", err)
	}

	user, err := domain.NewUser(username, string(hash), defaultRole)
	if err != nil {
		return err
	}

	// Adjuntar datos cifrados de email al usuario antes de persistir.
	user.EmailEncrypted = emailEncrypted
	user.EmailHash = emailHash

	if err := s.repo.Save(ctxTimeout, user); err != nil {
		return fmt.Errorf("failed to save registered user: %w", err)
	}
	return nil
}

// Login implementa AuthService.Login.
//
// Flujo de seguridad:
//  1. Rechaza contraseñas > 72 chars antes de llegar a bcrypt (prevención DoS).
//  2. Verifica account lockout ANTES de comparar la contraseña para no revelar
//     si las credenciales son válidas cuando la cuenta está bloqueada (timing attack).
//  3. Compara la contraseña con bcrypt; en fallo, incrementa el contador de intentos
//     y bloquea la cuenta si se alcanza domain.MaxFailedAttempts.
//  4. En éxito, resetea el contador y emite un Fat JWT con permisos embebidos y
//     el campo "ver" (token_version) para soporte de invalidación inmediata.
//  5. Genera y persiste un Refresh Token criptográficamente seguro (256 bits, base64).
//
// Errores posibles: domain.ErrInvalidCreds, domain.ErrAccountLocked.
func (s *authService) Login(ctx context.Context, username, password string) (string, string, error) {
	if len(password) > 72 {
		return "", "", domain.ErrInvalidCreds
	}

	ctxTimeout, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	user, err := s.repo.FindByUsername(ctxTimeout, username)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return "", "", domain.ErrInvalidCreds
		}
		return "", "", fmt.Errorf("database fetch failure: %w", err)
	}

	// 1. Verificar bloqueo de cuenta ANTES de comparar la contraseña.
	// No revelar si la contraseña es correcta cuando la cuenta está bloqueada:
	// evitamos el timing attack donde el atacante deduce que la cuenta existe.
	if user.IsLocked() {
		return "", "", domain.ErrAccountLocked
	}

	// 2. Verificar contraseña.
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		// Contraseña incorrecta → incrementar contador de intentos fallidos.
		locked := user.RecordFailedAttempt()
		// Persistir el nuevo estado del contador en la BD (fire-and-forget el error aquí,
		// pero loguearlo en producción para detectar problemas de escritura).
		_ = s.repo.Update(ctxTimeout, user)
		if locked {
			return "", "", domain.ErrAccountLocked
		}
		return "", "", domain.ErrInvalidCreds
	}

	// 3. Login exitoso → resetear contador.
	user.ResetFailedAttempts()
	_ = s.repo.Update(ctxTimeout, user)

	// 4. "Fat JWT": Integramos los permisos en el token para evitar viajes a DB en los handlers.
	// "ver" embebe token_version para permitir invalidación inmediata si cambian los permisos.
	// El middleware valida que JWT.ver == DB.token_version; si no coincide → 401.
	permArray := buildPermArray(user)

	claims := jwt.MapClaims{
		"sub":         user.Username,
		"uid":         user.ID,
		"ver":         user.TokenVersion, // Token version — invalidación por cambio de roles
		"exp":         time.Now().Add(15 * time.Minute).Unix(),
		"permissions": permArray,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	accessToken, err := token.SignedString(s.jwtSecret)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign jwt auth token: %w", err)
	}

	// 5. Generar y guardar Refresh Token (7 días).
	refreshToken := generateSecureToken()
	rt := &domain.RefreshToken{
		Token:     refreshToken,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}

	if err := s.repo.SaveRefreshToken(ctxTimeout, rt); err != nil {
		return "", "", fmt.Errorf("failed to save refresh token: %w", err)
	}

	return accessToken, refreshToken, nil
}

// RefreshTokens implementa AuthService.RefreshTokens.
//
// Aplica rotación estricta (Refresh Token Rotation):
//  1. Valida que el token exista en BD y no haya expirado.
//  2. Borra el token recibido inmediatamente (uso único — previene replay attacks).
//  3. Emite un nuevo Access Token (Fat JWT, TTL 15 min) con la token_version actual
//     del usuario, reflejando cambios de roles ocurridos desde el último login.
//  4. Emite y persiste un nuevo Refresh Token (TTL 7 días).
//
// Errores posibles: domain.ErrInvalidToken si el token no existe o expiró.
func (s *authService) RefreshTokens(ctx context.Context, refreshToken string) (string, string, error) {
	ctxTimeout, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	// 1. Validar el token actual en la BD.
	rt, err := s.repo.GetRefreshToken(ctxTimeout, refreshToken)
	if err != nil {
		return "", "", err // domain.ErrInvalidToken propagado
	}

	if time.Now().After(rt.ExpiresAt) {
		_ = s.repo.DeleteRefreshToken(ctxTimeout, refreshToken)
		return "", "", domain.ErrInvalidToken
	}

	// 2. Obtener el usuario asociado.
	user, err := s.repo.FindByID(ctxTimeout, rt.UserID)
	if err != nil {
		return "", "", fmt.Errorf("could not find user for refresh token: %w", err)
	}

	// 3. Rotación Estricta: Borrar el token viejo para que solo se use 1 vez.
	if err := s.repo.DeleteRefreshToken(ctxTimeout, refreshToken); err != nil {
		return "", "", fmt.Errorf("failed to delete old refresh token: %w", err)
	}

	// 4. Generar nuevo Access Token (Fat JWT) con la token_version actualizada.
	// Al refrescar, el nuevo token ya refleja la versión actual del usuario en DB,
	// incluyendo cualquier cambio de roles que haya ocurrido desde el login anterior.
	permArray := buildPermArray(user)

	claims := jwt.MapClaims{
		"sub":         user.Username,
		"uid":         user.ID,
		"ver":         user.TokenVersion,
		"exp":         time.Now().Add(15 * time.Minute).Unix(),
		"permissions": permArray,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	newAccessToken, err := token.SignedString(s.jwtSecret)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign new jwt: %w", err)
	}

	// 5. Generar nuevo Refresh Token.
	newRefreshToken := generateSecureToken()
	newRt := &domain.RefreshToken{
		Token:     newRefreshToken,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}

	if err := s.repo.SaveRefreshToken(ctxTimeout, newRt); err != nil {
		return "", "", fmt.Errorf("failed to save new refresh token: %w", err)
	}

	return newAccessToken, newRefreshToken, nil
}

// buildPermArray deduplica y construye el slice de permisos para el JWT.
// Recorre todos los roles del usuario y aplana sus permisos en un set para
// eliminar duplicados antes de serializar al claim "permissions" del token.
func buildPermArray(user *domain.User) []string {
	permsSet := make(map[string]struct{})
	for _, r := range user.Roles {
		for _, p := range r.Permissions {
			permsSet[p.Name] = struct{}{}
		}
	}
	permArray := make([]string, 0, len(permsSet))
	for p := range permsSet {
		permArray = append(permArray, p)
	}
	return permArray
}

// generateSecureToken genera un token de 256 bits criptográficamente seguro,
// codificado en base64 URL-safe. Usado para emitir Refresh Tokens.
func generateSecureToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// Logout implementa AuthService.Logout.
// Invalida todos los Refresh Tokens activos del usuario en base de datos.
// Los Access Tokens existentes no se pueden revocar activamente — expiran
// por TTL natural (máx. 15 min). Para invalidación inmediata de permisos,
// usar la lógica de token_version en AssignRoles/AssignPermissions.
func (s *authService) Logout(ctx context.Context, userID uint) error {
	ctxTimeout, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	_, err := s.repo.FindByID(ctxTimeout, userID)
	if err != nil {
		return err
	}

	return s.repo.DeleteAllRefreshTokens(ctxTimeout, userID)
}
