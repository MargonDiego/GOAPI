package application

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/diego/go-api/internal/domain"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type AuthService interface {
	Register(ctx context.Context, username, password string) error
	Login(ctx context.Context, username, password string) (string, error)
}

type authService struct {
	repo      domain.UserRepository
	jwtSecret []byte
}

func NewAuthService(repo domain.UserRepository, secret []byte) AuthService {
	return &authService{repo: repo, jwtSecret: secret}
}

func (s *authService) Register(ctx context.Context, username, password string) error {
	if len(password) < 8 || len(password) > 72 {
		return fmt.Errorf("%w: password length must be 8-72 characters", domain.ErrInvalidInput)
	}

	// 1. Añadimos un Time-bound context para evitar leaks esperando lectura a PostgreSQL
	ctxTimeout, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	_, err := s.repo.FindByUsername(ctxTimeout, username)
	if err == nil {
		return domain.ErrUserAlreadyExists
	}
	if !errors.Is(err, domain.ErrUserNotFound) {
		return fmt.Errorf("unexpected database error checking username: %w", err)
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

	if err := s.repo.Save(ctxTimeout, user); err != nil {
		return fmt.Errorf("failed to save registered user: %w", err)
	}
	return nil
}

func (s *authService) Login(ctx context.Context, username, password string) (string, error) {
	if len(password) > 72 {
		return "", domain.ErrInvalidCreds
	}

	ctxTimeout, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	user, err := s.repo.FindByUsername(ctxTimeout, username)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return "", domain.ErrInvalidCreds
		}
		return "", fmt.Errorf("database fetch failure: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return "", domain.ErrInvalidCreds
	}

	// "Fat JWT": Integramos los permisos en el token para evitar viajes a DB en los handlers
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

	claims := jwt.MapClaims{
		"sub":         user.Username,
		"exp":         time.Now().Add(24 * time.Hour).Unix(),
		"permissions": permArray, // Se encriptan y firman aquí. O(0) en base de datos.
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(s.jwtSecret)
	if err != nil {
		return "", fmt.Errorf("failed to sign jwt auth token: %w", err)
	}
	return signedToken, nil
}
