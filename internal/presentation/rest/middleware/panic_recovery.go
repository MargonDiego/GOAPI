package middleware

import (
	"net/http"
	"runtime/debug"

	"github.com/rs/zerolog/log"
)

// PanicRecovery recupera panics en cualquier handler y devuelve 500
// en lugar de crashear el servidor entero.
//
// El stack trace se loguea a nivel Error para debugging.
// El cliente recibe un mensaje genÃ©rico sin detalles internos.
//
// DEBE ser el middleware MÃS EXTERNO (primero en la cadena) para
// capturar panics de cualquier middleware o handler downstream.
func PanicRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Error().
					Interface("panic", rec).
					Str("stack", string(debug.Stack())).
					Str("method", r.Method).
					Str("path", r.URL.Path).
					Msg("PANIC RECOVERED")

				respondError(w, http.StatusInternalServerError, "internal server error")
			}
		}()

		next.ServeHTTP(w, r)
	})
}
