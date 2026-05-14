package application

import "context"

// actorKey es un tipo privado para evitar colisiones con otras claves de contexto.
type actorKey struct{}

// scopeKey es un tipo privado para el scoping administrativo.
type scopeKey struct{}

// ipKey es un tipo privado para la dirección IP del cliente.
type ipKey struct{}

// uaKey es un tipo privado para el User-Agent del cliente.
type uaKey struct{}

// WithActor inyecta el ID del usuario autenticado en el contexto.
// Debe llamarse en los handlers antes de invocar servicios que requieren auditoría.
func WithActor(ctx context.Context, userID uint) context.Context {
	return context.WithValue(ctx, actorKey{}, userID)
}

// ActorFromContext extrae el ID del actor del contexto.
// Retorna (0, false) si no hay actor inyectado.
func ActorFromContext(ctx context.Context) (uint, bool) {
	uid, ok := ctx.Value(actorKey{}).(uint)
	return uid, ok
}

// WithScope inyecta el scope del usuario autenticado en el contexto.
func WithScope(ctx context.Context, scope string) context.Context {
	return context.WithValue(ctx, scopeKey{}, scope)
}

// ScopeFromContext extrae el scope del actor del contexto.
// Retorna ("", false) si no hay scope inyectado.
func ScopeFromContext(ctx context.Context) (string, bool) {
	scope, ok := ctx.Value(scopeKey{}).(string)
	return scope, ok
}

// WithIP inyecta la dirección IP del cliente en el contexto.
func WithIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, ipKey{}, ip)
}

// IPFromContext extrae la IP del cliente del contexto.
// Retorna ("", false) si no hay IP inyectada.
func IPFromContext(ctx context.Context) (string, bool) {
	ip, ok := ctx.Value(ipKey{}).(string)
	return ip, ok
}

// WithUserAgent inyecta el User-Agent del cliente en el contexto.
func WithUserAgent(ctx context.Context, ua string) context.Context {
	return context.WithValue(ctx, uaKey{}, ua)
}

// UserAgentFromContext extrae el User-Agent del cliente del contexto.
// Retorna ("", false) si no hay User-Agent inyectado.
func UserAgentFromContext(ctx context.Context) (string, bool) {
	ua, ok := ctx.Value(uaKey{}).(string)
	return ua, ok
}
