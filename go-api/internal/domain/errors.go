// Package domain define las entidades, errores y contratos del núcleo de negocio.
package domain

import (
	"net/http"
	"time"
)

// --- Constantes de Account Lockout ---

const (
	MaxFailedAttempts = 5                // Intentos antes del bloqueo
	LockDuration      = 15 * time.Minute // Duración del bloqueo
)

// --- Errores Tipados del Dominio ---
//
// AppError es un error estructurado que incluye:
//   - Code: código de error legible por máquina (ej: "USER_NOT_FOUND")
//   - Message: descripción humana (misma semántica que errors.New)
//   - Status: código HTTP RESTful asociado
//
// Beneficios vs sentinel errors de Go estándar:
//   - Los handlers NO necesitan mapear errores a HTTP — el error ya sabe su status.
//   - El código de error viaja en la respuesta JSON (campo "code").
//   - Los clientes pueden hacer switch por code en lugar de parsear mensajes.
//   - Debugging: el log muestra USER_NOT_FOUND en lugar de "user not found" genérico.
//
// Compatibilidad total con errors.Is() y errors.As().
// Las variables exportadas son punteros a structs — cada una es única y comparable.
type AppError struct {
	Code    string `json:"code"`    // Código de error legible por máquina
	Message string `json:"message"` // Descripción humana del error
	Status  int    `json:"status"`  // Código HTTP asociado

	Err error `json:"-"` // Error subyacente (opcional, para wrapping)
}

// Error implementa la interfaz error. Retorna el código + mensaje.
func (e *AppError) Error() string {
	if e.Err != nil {
		return e.Code + ": " + e.Message + " — " + e.Err.Error()
	}
	return e.Code + ": " + e.Message
}

// Unwrap permite que errors.Is() y errors.As() atraviesen wraps.
func (e *AppError) Unwrap() error { return e.Err }

// --- Errores del Dominio ---

var (
	// 404 — Recurso no encontrado
	ErrUserNotFound       = &AppError{Code: "USER_NOT_FOUND", Message: "user not found", Status: http.StatusNotFound}
	ErrRoleNotFound       = &AppError{Code: "ROLE_NOT_FOUND", Message: "role not found", Status: http.StatusNotFound}
	ErrPermissionNotFound = &AppError{Code: "PERMISSION_NOT_FOUND", Message: "permission not found", Status: http.StatusNotFound}

	// 401 — Autenticación
	ErrInvalidCreds = &AppError{Code: "INVALID_CREDENTIALS", Message: "invalid credentials", Status: http.StatusUnauthorized}
	ErrInvalidToken = &AppError{Code: "INVALID_TOKEN", Message: "invalid or expired refresh token", Status: http.StatusUnauthorized}

	// 400 — Validación
	ErrInvalidInput = &AppError{Code: "INVALID_INPUT", Message: "invalid user input data", Status: http.StatusBadRequest}

	// 429 — Rate limit / bloqueo
	ErrAccountLocked = &AppError{Code: "ACCOUNT_LOCKED", Message: "account temporarily locked due to multiple failed attempts", Status: http.StatusTooManyRequests}

	// 409 — Conflicto (recurso duplicado)
	ErrUserAlreadyExists       = &AppError{Code: "USER_ALREADY_EXISTS", Message: "username already exists", Status: http.StatusConflict}
	ErrEmailAlreadyExists      = &AppError{Code: "EMAIL_ALREADY_EXISTS", Message: "email already registered", Status: http.StatusConflict}
	ErrRoleAlreadyExists       = &AppError{Code: "ROLE_ALREADY_EXISTS", Message: "role already exists", Status: http.StatusConflict}
	ErrPermissionAlreadyExists = &AppError{Code: "PERMISSION_ALREADY_EXISTS", Message: "permission already exists", Status: http.StatusConflict}

	// 403 — Autorización
	ErrInsufficientPerms = &AppError{Code: "INSUFFICIENT_PERMISSIONS", Message: "insufficient permissions", Status: http.StatusForbidden}
	ErrRoleImmutable     = &AppError{Code: "ROLE_IMMUTABLE", Message: "system role cannot be modified or deleted", Status: http.StatusForbidden}
	ErrScopeMismatch     = &AppError{Code: "SCOPE_MISMATCH", Message: "operation not allowed for this scope", Status: http.StatusForbidden}
)
