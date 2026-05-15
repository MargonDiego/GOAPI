package domain

import "time"

// RefreshToken representa un token de larga duraciÃ³n para renovar sesiones
// sin re-autenticaciÃ³n. Se almacena en base de datos y se rota en cada uso.
type RefreshToken struct {
	Token     string
	UserID    uint
	ExpiresAt time.Time
}
