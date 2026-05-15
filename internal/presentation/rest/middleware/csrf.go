package middleware

import (
	"net/http"
	"slices"
	"strings"
)

// CSRF protege endpoints de mutacion (POST/PUT/DELETE) contra Cross-Site Request Forgery.
//
// Estrategia: validar el header Origin contra los origenes permitidos (CORS_ORIGINS).
// Si el Origin no coincide con ningun origen permitido, se rechaza con 403.
//
// Esto es necesario porque las cookies HttpOnly se envian automaticamente
// en cada request, incluso desde sitios maliciosos. Validar Origin es la defensa
// estandar OWASP para APIs que usan cookies de sesion.
//
// Metodos seguros (GET/HEAD/OPTIONS) no requieren check CSRF.
func CSRF(allowedOrigins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Solo aplica a metodos que cambian estado
			switch r.Method {
			case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
				origin := r.Header.Get("Origin")
				if origin == "" {
					// Sin Origin header: podria ser una app mobile o un request server-to-server.
					// Permitir con Referer como fallback.
					referer := r.Header.Get("Referer")
					if referer == "" {
						respondError(w, http.StatusForbidden, "CSRF validation failed: missing Origin header")
						return
					}
					// Verificar Referer contra origenes permitidos
					if !matchesOrigin(referer, allowedOrigins) {
						respondError(w, http.StatusForbidden, "CSRF validation failed: invalid Referer")
						return
					}
					next.ServeHTTP(w, r)
					return
				}

				if !slices.Contains(allowedOrigins, origin) {
					respondError(w, http.StatusForbidden, "CSRF validation failed: untrusted origin")
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// matchesOrigin verifica si el Referer empieza con alguno de los origenes permitidos.
func matchesOrigin(referer string, allowedOrigins []string) bool {
	for _, origin := range allowedOrigins {
		if strings.HasPrefix(referer, origin) {
			return true
		}
	}
	return false
}
