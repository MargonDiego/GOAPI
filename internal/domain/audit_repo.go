package domain

import "context"

// AuditLog representa un registro de auditorÃ­a de cambios en el sistema.
type AuditLog struct {
	ID         uint
	Action     string
	ActorID    uint
	TargetType string
	TargetID   uint
	OldValue   string
	NewValue   string
	IPAddress  string
	UserAgent  string
	CreatedAt  string
}

// AuditRepository define el contrato para persistir registros de auditorÃ­a.
type AuditRepository interface {
	// Log persiste un registro de auditorÃ­a.
	Log(ctx context.Context, log *AuditLog) error
}
