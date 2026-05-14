package middleware

import (
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

// responseWriter wrappea http.ResponseWriter para capturar el status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{w, http.StatusOK}
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// RequestLogger es un middleware que emite un log estructurado por cada request HTTP.
// Captura: método, path, status, duración y IP del cliente.
func RequestLogger() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := newResponseWriter(w)

			next.ServeHTTP(rw, r)

			duration := time.Since(start)

			event := log.Info()
			if rw.statusCode >= 500 {
				event = log.Error()
			} else if rw.statusCode >= 400 {
				event = log.Warn()
			}

			event.
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Int("status", rw.statusCode).
				Dur("duration_ms", duration).
				Str("remote_addr", r.RemoteAddr).
				Msg("request")
		})
	}
}
