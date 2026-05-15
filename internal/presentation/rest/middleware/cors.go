package middleware

import (
	"net/http"
)

// CORS retorna un middleware que aplica cabeceras CORS restrictivas.
// Recibe los orígenes permitidos como parámetros (desde configuración).
// En producción, pasar los dominios exactos del frontend (ej: "https://miapp.com").
// Nunca usar wildcard con credentials.
//
// Ejemplo: r.Use(middleware.CORS("http://localhost:3000", "https://miapp.com"))
func CORS(allowedOrigins ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		allowed[o] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin == "" || allowed[origin] {
				if origin != "" {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
				w.Header().Set("Access-Control-Max-Age", "86400")
			}

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
