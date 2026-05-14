// Package domain define las entidades, errores y contratos del núcleo de negocio.
package domain

import (
	"errors"
	"time"
)

// --- Constantes de Account Lockout ---

const (
	MaxFailedAttempts = 5                // Intentos antes del bloqueo
	LockDuration      = 15 * time.Minute // Duración del bloqueo
)

// --- Errores del Dominio ---
// Cada error representa una condición de negocio específica.
// Los handlers los mapean a códigos HTTP; los servicios los usan para control de flujo.

var (
	ErrUserNotFound            = errors.New("user not found")
	ErrInvalidCreds            = errors.New("invalid credentials")
	ErrUserAlreadyExists       = errors.New("username already exists")
	ErrEmailAlreadyExists      = errors.New("email already registered")
	ErrInsufficientPerms       = errors.New("insufficient permissions")
	ErrInvalidInput            = errors.New("invalid user input data")
	ErrRoleNotFound            = errors.New("role not found")
	ErrRoleAlreadyExists       = errors.New("role already exists")
	ErrPermissionNotFound      = errors.New("permission not found")
	ErrPermissionAlreadyExists = errors.New("permission already exists")
	ErrInvalidToken            = errors.New("invalid or expired refresh token")
	ErrAccountLocked           = errors.New("account temporarily locked due to multiple failed attempts")
	ErrRoleImmutable           = errors.New("system role cannot be modified or deleted")
	ErrScopeMismatch           = errors.New("operation not allowed for this scope")
)
