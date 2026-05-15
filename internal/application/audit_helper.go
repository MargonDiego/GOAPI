package application

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/MargonDiego/GOAPI/internal/domain"
)

// auditService encapsula la lÃ³gica de auditorÃ­a reutilizable entre servicios.
type auditService struct {
	auditRepo domain.AuditRepository
}

// newAuditService construye un auditService con el repositorio inyectado.
// Si auditRepo es nil, los logs se ignoran silenciosamente (nil-safe para testing).
func newAuditService(auditRepo domain.AuditRepository) auditService {
	return auditService{auditRepo: auditRepo}
}

// log registra una acciÃ³n de auditorÃ­a si hay un actor en el contexto y un auditRepo configurado.
// oldValue y newValue se serializan a JSON; si fallan, se almacenan como string vacÃ­o.
func (a *auditService) log(ctx context.Context, action, targetType string, targetID uint, oldValue, newValue any) {
	if a.auditRepo == nil {
		return
	}

	actorID, ok := ActorFromContext(ctx)
	if !ok {
		// Sin actor no hay trazabilidad â€” no registramos.
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

	// Enriquecer con metadatos del request si estÃ¡n disponibles.
	if ip, ok := IPFromContext(ctx); ok {
		log.IPAddress = ip
	}
	if ua, ok := UserAgentFromContext(ctx); ok {
		log.UserAgent = ua
	}

	// Ignorar error de auditorÃ­a para no interrumpir la operaciÃ³n principal.
	_ = a.auditRepo.Log(ctx, log)
}

// marshalAuditValue serializa un valor a JSON para auditorÃ­a.
// Retorna string vacÃ­o y error si la serializaciÃ³n falla.
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

// --- Scoping helpers ---

// canAccessScope verifica si el actor tiene acceso a un recurso del scope dado.
// Reglas:
//   - Actor con scope vacÃ­o ("") = super-admin, accede a todo.
//   - Actor con scope no vacÃ­o = solo accede a recursos de su scope o scope vacÃ­o.
func canAccessScope(actorScope, resourceScope string) bool {
	if actorScope == "" {
		return true // super-admin
	}
	return resourceScope == "" || resourceScope == actorScope
}

// assertScopeAccess devuelve ErrScopeMismatch si el actor no tiene acceso al scope del recurso.
func assertScopeAccess(ctx context.Context, resourceScope string) error {
	actorScope, ok := ScopeFromContext(ctx)
	if !ok {
		return domain.ErrScopeMismatch // Sin scope en contexto = no autorizado
	}
	if !canAccessScope(actorScope, resourceScope) {
		return domain.ErrScopeMismatch
	}
	return nil
}
