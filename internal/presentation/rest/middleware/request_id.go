package middleware

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

type requestIDKey struct{}

// RequestID inyecta un UUID Ãºnico en cada request para trazabilidad end-to-end.
//
// Comportamiento:
//   - Si el cliente envÃ­a X-Request-ID, se reutiliza (trazabilidad cross-service).
//   - Si no, se genera un UUID v4 nuevo.
//   - El ID se agrega al header de respuesta X-Request-ID.
//   - Se almacena en el contexto para que handlers y middlewares lo lean.
//
// El request_logger usa este ID automÃ¡ticamente cuando estÃ¡ disponible en el contexto.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := r.Header.Get("X-Request-ID")
		if rid == "" {
			rid = uuid.New().String()
		}

		w.Header().Set("X-Request-ID", rid)
		ctx := context.WithValue(r.Context(), requestIDKey{}, rid)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetRequestID extrae el ID de request del contexto.
// Retorna string vacÃ­o si no se configurÃ³ el middleware RequestID.
func GetRequestID(ctx context.Context) string {
	if rid, ok := ctx.Value(requestIDKey{}).(string); ok {
		return rid
	}
	return ""
}
