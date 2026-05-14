package persistence

import (
	"context"

	"github.com/diego/go-api/internal/domain"
	"gorm.io/gorm"
)

type auditRepository struct {
	db *gorm.DB
}

// NewAuditRepository construye un auditRepository con la conexión GORM inyectada.
func NewAuditRepository(db *gorm.DB) domain.AuditRepository {
	return &auditRepository{db: db}
}

// Log persiste un registro de auditoría en la base de datos.
func (r *auditRepository) Log(ctx context.Context, log *domain.AuditLog) error {
	dbLog := &AuditLog{
		Action:     log.Action,
		ActorID:    log.ActorID,
		TargetType: log.TargetType,
		TargetID:   log.TargetID,
		OldValue:   log.OldValue,
		NewValue:   log.NewValue,
		IPAddress:  log.IPAddress,
		UserAgent:  log.UserAgent,
	}
	return r.db.WithContext(ctx).Create(dbLog).Error
}
