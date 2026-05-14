package domain

import (
	"strings"
	"time"
)

// User es la entidad central del dominio.
// El Email NUNCA llega aquí en texto plano desde la BD — se descifra en el servicio
// solo cuando es necesario mostrarlo (ej: endpoint de perfil).
// EmailEncrypted y EmailHash son los valores que viven en Postgres.
type User struct {
	ID             uint
	Username       string
	PasswordHash   string
	EmailEncrypted string     // AES-256-GCM, IV aleatorio, base64 — confidencialidad
	EmailHash      string     // HMAC-SHA256, determinista — permite WHERE email_hash = ?
	FailedAttempts int        // Contador de intentos fallidos consecutivos
	LockedUntil    *time.Time // nil = no bloqueado; not nil = bloqueado hasta esa hora
	TokenVersion   int        // Versión del token: se incrementa al cambiar roles/permisos
	Scope          string     // Dominio/organización al que pertenece el usuario
	Roles          []Role
}

// --- Factory ---

// NewUser es la Fábrica (Factory) del Dominio Puro.
// Encapsula las invariantes de creación de usuario.
func NewUser(username, passwordHash string, defaultRole Role) (*User, error) {
	username = strings.TrimSpace(username)
	if len(username) < 3 {
		return nil, ErrInvalidInput
	}
	if passwordHash == "" {
		return nil, ErrInvalidInput
	}

	return &User{
		Username:     username,
		PasswordHash: passwordHash,
		Roles:        []Role{defaultRole},
	}, nil
}

// --- Account Lockout ---

// IsLocked informa si la cuenta está bloqueada EN ESTE MOMENTO.
// Separar esta lógica del servicio permite testearla sin infraestructura.
func (u *User) IsLocked() bool {
	if u.LockedUntil == nil {
		return false
	}
	return time.Now().Before(*u.LockedUntil)
}

// RecordFailedAttempt incrementa el contador y bloquea la cuenta si alcanza el máximo.
// Retorna true si la cuenta quedó bloqueada como consecuencia de ESTE intento.
func (u *User) RecordFailedAttempt() bool {
	u.FailedAttempts++
	if u.FailedAttempts >= MaxFailedAttempts {
		lockedUntil := time.Now().Add(LockDuration)
		u.LockedUntil = &lockedUntil
		return true
	}
	return false
}

// ResetFailedAttempts limpia el contador tras un login exitoso.
func (u *User) ResetFailedAttempts() {
	u.FailedAttempts = 0
	u.LockedUntil = nil
}

// --- Permissions ---

// HasPermission verifica si el usuario posee un permiso específico a través
// de cualquiera de sus roles asignados. Búsqueda O(n*m) — los roles/permisos
// son conjuntos pequeños en memoria (embebidos en el Fat JWT).
func (u *User) HasPermission(p string) bool {
	for _, r := range u.Roles {
		for _, perm := range r.Permissions {
			if perm.Name == p {
				return true
			}
		}
	}
	return false
}
