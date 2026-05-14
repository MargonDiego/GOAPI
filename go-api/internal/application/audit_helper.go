package application

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/diego/go-api/internal/domain"
)

// auditService encapsula la lógica de auditoría reutilizable entre servicios.
type auditService struct {
	auditRepo domain.AuditRepository
}

// newAuditService construye un auditService con el repositorio inyectado.
// Si auditRepo es nil, los logs se ignoran silenciosamente (nil-safe para testing).
func newAuditService(auditRepo domain.AuditRepository) auditService {
	return auditService{auditRepo: auditRepo}
}

// log registra una acción de auditoría si hay un actor en el contexto y un auditRepo configurado.
// oldValue y newValue se serializan a JSON; si fallan, se almacenan como string vacío.
func (a *auditService) log(ctx context.Context, action, targetType string, targetID uint, oldValue, newValue any) {
	if a.auditRepo == nil {
		return
	}

	actorID, ok := ActorFromContext(ctx)
	if !ok {
		// Sin actor no hay trazabilidad — no registramos.
		return
	}

	oldJSON, _ := marshalAuditValue(oldValue)
	newJSON, _ := marshalAuditValue(newValue)

	log := &domain.AuditLog{
		Action:     action,
		ActorID:    actorID,
		TargetType: targetType,
		TargetID:   targetID,
		OldValue:   oldJSON,
		NewValue:   newJSON,
	}

	// Ignorar error de auditoría para no interrumpir la operación principal.
	_ = a.auditRepo.Log(ctx, log)
}

// marshalAuditValue serializa un valor a JSON para auditoría.
// Retorna string vacío y error si la serialización falla.
func marshalAuditValue(v any) (string, error) {
	if v == nil {
		return "", nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("audit marshal failed: %w", err)
	}
	return string(b), nil
}
