package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MargonDiego/GOAPI/internal/infrastructure/cache"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

var testSecret = []byte("my_super_secret_key")

// generateTestToken crea un JWT vÃ¡lido para las pruebas.
// Incluye los claims requeridos por el middleware: sub, uid, ver, permissions.
func generateTestToken(username string, permissions []string, expired bool) string {
	claims := jwt.MapClaims{
		"sub":         username,
		"uid":         float64(1), // userID fijo para tests
		"ver":         float64(1), // token_version = 1 (match con el cache default)
		"permissions": permissions,
	}

	if expired {
		claims["exp"] = time.Now().Add(-1 * time.Hour).Unix()
	} else {
		claims["exp"] = time.Now().Add(1 * time.Hour).Unix()
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(testSecret)
	return tokenString
}

func TestRequireAuth(t *testing.T) {
	t.Parallel()

	mw := NewAuthMiddleware(testSecret, nil, cache.NewTokenVersionCache(30*time.Second))
	// Precargar el cache con la versiÃ³n esperada para evitar el fallback a DB (repo es nil en tests).
	mw.versionCache.Set(1, 1)

	// Handler ficticio que simplemente retorna 200 OK si el middleware lo deja pasar
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, ok := GetSessionFromContext(r.Context())
		if ok {
			// Escribimos el nombre del usuario en el header para testear que el context funciona
			w.Header().Set("X-Username", session.Username)
		}
		w.WriteHeader(http.StatusOK)
	})

	handlerToTest := mw.RequireAuth()(nextHandler)

	tests := []struct {
		name           string
		setupHeader    func(req *http.Request)
		expectedStatus int
		expectedUser   string
	}{
		{
			name: "Error: Sin Header de AutorizaciÃ³n",
			setupHeader: func(req *http.Request) {
				// No seteamos nada
			},
			expectedStatus: http.StatusUnauthorized,
			expectedUser:   "",
		},
		{
			name: "Error: Formato de Header InvÃ¡lido",
			setupHeader: func(req *http.Request) {
				req.Header.Set("Authorization", "Token raro")
			},
			expectedStatus: http.StatusUnauthorized,
			expectedUser:   "",
		},
		{
			name: "Error: Token Expirado",
			setupHeader: func(req *http.Request) {
				token := generateTestToken("expireduser", []string{"read"}, true)
				req.Header.Set("Authorization", "Bearer "+token)
			},
			expectedStatus: http.StatusUnauthorized,
			expectedUser:   "",
		},
		{
			name: "Ã‰xito: Token VÃ¡lido",
			setupHeader: func(req *http.Request) {
				token := generateTestToken("validuser", []string{"read"}, false)
				req.Header.Set("Authorization", "Bearer "+token)
			},
			expectedStatus: http.StatusOK,
			expectedUser:   "validuser",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
			tt.setupHeader(req)
			rr := httptest.NewRecorder()

			handlerToTest.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)
			if tt.expectedUser != "" {
				assert.Equal(t, tt.expectedUser, rr.Header().Get("X-Username"))
			}
		})
	}
}

func TestRequirePermission(t *testing.T) {
	t.Parallel()

	mw := NewAuthMiddleware(testSecret, nil, cache.NewTokenVersionCache(30*time.Second))

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// El middleware de permisos espera que el de Auth ya haya corrido e inyectado la sesiÃ³n
	handlerToTest := mw.RequirePermission("write:data")(nextHandler)

	tests := []struct {
		name           string
		session        *UserSession // Si es nil, no hay sesiÃ³n en el contexto
		expectedStatus int
	}{
		{
			name:           "Error: Contexto sin sesiÃ³n (AuthMw no corriÃ³)",
			session:        nil,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "Error: Usuario sin el permiso requerido",
			session: &UserSession{
				Username:    "readonly",
				Permissions: map[string]bool{"read:data": true},
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name: "Ã‰xito: Usuario con el permiso exacto",
			session: &UserSession{
				Username:    "writer",
				Permissions: map[string]bool{"write:data": true, "read:data": true},
			},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodPost, "/api/write", nil)
			if tt.session != nil {
				ctx := context.WithValue(req.Context(), userSessionKey, *tt.session)
				req = req.WithContext(ctx)
			}

			rr := httptest.NewRecorder()
			handlerToTest.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)
		})
	}
}
