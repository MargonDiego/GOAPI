package middleware

import "net/http"

// SecurityHeaders agrega cabeceras de seguridad estándar a cada respuesta.
//
// Headers aplicados:
//   - X-Content-Type-Options: nosniff (previene MIME sniffing)
//   - X-Frame-Options: DENY (previene clickjacking)
//   - Strict-Transport-Security (HSTS) — solo en producción, configura caché de 1 año
//   - X-XSS-Protection: 1; mode=block (filtro XSS, legacy pero soportado)
//   - Referrer-Policy: strict-origin-when-cross-origin
//   - Content-Security-Policy: default-src 'self' (base restrictiva)
//
// En producción, agregar HSTS y CSP más específicas según el deployment.
func SecurityHeaders(env string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			w.Header().Set("Content-Security-Policy", "default-src 'self'")

			if env == "production" {
				w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}

			next.ServeHTTP(w, r)
		})
	}
}
