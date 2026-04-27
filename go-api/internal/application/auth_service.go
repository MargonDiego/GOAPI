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

type AuthService interface {
	Register(ctx context.Context, username, password, email string) error
	Login(ctx context.Context, username, password string) (accessToken string, refreshToken string, err error)
	RefreshTokens(ctx context.Context, refreshToken string) (accessToken string, newRefreshToken string, err error)
	Logout(ctx context.Context, userID uint) error
}

type authService struct {
	repo      domain.UserRepository
	jwtSecret []byte
	enc       *appcrypto.Encryptor
}

func NewAuthService(repo domain.UserRepository, secret []byte, enc *appcrypto.Encryptor) AuthService {
	return &authService{repo: repo, jwtSecret: secret, enc: enc}
}

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
	permArray := buildPermArray(user)

	claims := jwt.MapClaims{
		"sub":         user.Username,
		"uid":         user.ID,
		"exp":         time.Now().Add(15 * time.Minute).Unix(), // Access Token corto (15 min)
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

	// 4. Generar nuevo Access Token (Fat JWT).
	permArray := buildPermArray(user)

	claims := jwt.MapClaims{
		"sub":         user.Username,
		"uid":         user.ID,
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

func generateSecureToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func (s *authService) Logout(ctx context.Context, userID uint) error {
	ctxTimeout, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	_, err := s.repo.FindByID(ctxTimeout, userID)
	if err != nil {
		return err
	}

	return s.repo.DeleteAllRefreshTokens(ctxTimeout, userID)
}
