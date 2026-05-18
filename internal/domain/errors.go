// Package domain define las entidades, errores y contratos del nÃºcleo de negocio.
package domain

import (
	"net/http"
	"time"
)

// --- Constantes de Account Lockout ---

const (
	MaxFailedAttempts = 5                // Intentos antes del bloqueo
	LockDuration      = 15 * time.Minute // DuraciÃ³n del bloqueo
)

// --- Errores Tipados del Dominio ---
//
// AppError es un error estructurado que incluye:
//   - Code: cÃ³digo de error legible por mÃ¡quina (ej: "USER_NOT_FOUND")
//   - Message: descripciÃ³n humana (misma semÃ¡ntica que errors.New)
//   - Status: cÃ³digo HTTP RESTful asociado
//
// Beneficios vs sentinel errors de Go estÃ¡ndar:
//   - Los handlers NO necesitan mapear errores a HTTP â€” el error ya sabe su status.
//   - El cÃ³digo de error viaja en la respuesta JSON (campo "code").
//   - Los clientes pueden hacer switch por code en lugar de parsear mensajes.
//   - Debugging: el log muestra USER_NOT_FOUND en lugar de "user not found" genÃ©rico.
//
// Compatibilidad total con errors.Is() y errors.As().
// Las variables exportadas son punteros a structs â€” cada una es Ãºnica y comparable.
type AppError struct {
	Code    string `json:"code"`    // CÃ³digo de error legible por mÃ¡quina
	Message string `json:"message"` // DescripciÃ³n humana del error
	Status  int    `json:"status"`  // CÃ³digo HTTP asociado

	Err error `json:"-"` // Error subyacente (opcional, para wrapping)
}

// Error implementa la interfaz error. Retorna el cÃ³digo + mensaje.
func (e *AppError) Error() string {
	if e.Err != nil {
		return e.Code + ": " + e.Message + " â€” " + e.Err.Error()
	}
	return e.Code + ": " + e.Message
}

// Unwrap permite que errors.Is() y errors.As() atraviesen wraps.
func (e *AppError) Unwrap() error { return e.Err }

// --- Errores del Dominio ---

var (
	// 404 â€” Recurso no encontrado
	ErrUserNotFound       = &AppError{Code: "USER_NOT_FOUND", Message: "user not found", Status: http.StatusNotFound}
	ErrRoleNotFound       = &AppError{Code: "ROLE_NOT_FOUND", Message: "role not found", Status: http.StatusNotFound}
	ErrPermissionNotFound = &AppError{Code: "PERMISSION_NOT_FOUND", Message: "permission not found", Status: http.StatusNotFound}

	// 401 â€” AutenticaciÃ³n
	ErrInvalidCreds = &AppError{Code: "INVALID_CREDENTIALS", Message: "invalid credentials", Status: http.StatusUnauthorized}
	ErrInvalidToken = &AppError{Code: "INVALID_TOKEN", Message: "invalid or expired refresh token", Status: http.StatusUnauthorized}

	// 400 â€” ValidaciÃ³n
	ErrInvalidInput = &AppError{Code: "INVALID_INPUT", Message: "invalid user input data", Status: http.StatusBadRequest}

	// 404 – Recurso de convivencia no encontrado
	ErrEstudianteNotFound = &AppError{Code: "ESTUDIANTE_NOT_FOUND", Message: "student not found", Status: http.StatusNotFound}

	// 400 – RUT chileno inválido (módulo 11)
	ErrRutInvalido = &AppError{Code: "RUT_INVALIDO", Message: "rut chileno inválido", Status: http.StatusBadRequest}

	// 429 â€” Rate limit / bloqueo
	ErrAccountLocked = &AppError{Code: "ACCOUNT_LOCKED", Message: "account temporarily locked due to multiple failed attempts", Status: http.StatusTooManyRequests}

	// 409 â€” Conflicto (recurso duplicado)
	ErrUserAlreadyExists       = &AppError{Code: "USER_ALREADY_EXISTS", Message: "username already exists", Status: http.StatusConflict}
	ErrEmailAlreadyExists      = &AppError{Code: "EMAIL_ALREADY_EXISTS", Message: "email already registered", Status: http.StatusConflict}
	ErrRoleAlreadyExists       = &AppError{Code: "ROLE_ALREADY_EXISTS", Message: "role already exists", Status: http.StatusConflict}
	ErrPermissionAlreadyExists = &AppError{Code: "PERMISSION_ALREADY_EXISTS", Message: "permission already exists", Status: http.StatusConflict}
	ErrEstudianteDuplicado     = &AppError{Code: "ESTUDIANTE_DUPLICADO", Message: "estudiante con ese RUT ya existe", Status: http.StatusConflict}

	// 404 - Incidencias
	ErrIncidenciaNotFound = &AppError{Code: "INCIDENCIA_NOT_FOUND", Message: "incidencia not found", Status: http.StatusNotFound}
	ErrAdjuntoNotFound    = &AppError{Code: "ADJUNTO_NOT_FOUND", Message: "adjunto not found", Status: http.StatusNotFound}
	ErrApelacionNotFound  = &AppError{Code: "APELACION_NOT_FOUND", Message: "apelacion not found", Status: http.StatusNotFound}

	// 409 - Transicion de estado invalida
	ErrTransicionInvalida    = &AppError{Code: "TRANSICION_INVALIDA", Message: "transition not allowed from current state", Status: http.StatusConflict}
	ErrApelacionFueraDePlazo = &AppError{Code: "APELACION_FUERA_DE_PLAZO", Message: "apelacion fuera del plazo permitido", Status: http.StatusConflict}

	// 400 - Validacion de negocio
	ErrResolucionSinFundamento = &AppError{Code: "RESOLUCION_SIN_FUNDAMENTO", Message: "la fundamentacion de la resolucion es obligatoria", Status: http.StatusBadRequest}
	ErrMedidaDesproporcionada  = &AppError{Code: "MEDIDA_DESPROPORCIONADA", Message: "expulsion y cancelacion solo aplican a faltas gravisimas", Status: http.StatusBadRequest}

	// 403 - Autorizacion
	ErrInsufficientPerms = &AppError{Code: "INSUFFICIENT_PERMISSIONS", Message: "insufficient permissions", Status: http.StatusForbidden}
	ErrRoleImmutable     = &AppError{Code: "ROLE_IMMUTABLE", Message: "system role cannot be modified or deleted", Status: http.StatusForbidden}
	ErrScopeMismatch     = &AppError{Code: "SCOPE_MISMATCH", Message: "operation not allowed for this scope", Status: http.StatusForbidden}
)
