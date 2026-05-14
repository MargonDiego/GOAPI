package domain

import "time"

// RefreshToken representa un token de larga duración para renovar sesiones
// sin re-autenticación. Se almacena en base de datos y se rota en cada uso.
type RefreshToken struct {
	Token     string
	UserID    uint
	ExpiresAt time.Time
}
