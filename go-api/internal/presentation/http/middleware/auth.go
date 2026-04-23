package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/diego/go-api/internal/presentation/http/handlers"
)

type contextKey string

const userSessionKey contextKey = "user_session"

// UserSession almacena los datos extraídos en memoria (Cero I/O)
type UserSession struct {
	Username    string
	Permissions map[string]bool
}

func GetSessionFromContext(ctx context.Context) (UserSession, bool) {
	session, ok := ctx.Value(userSessionKey).(UserSession)
	return session, ok
}

// GetUsernameFromContext se mantiene por retrocompatibilidad con handlers existentes
func GetUsernameFromContext(ctx context.Context) (string, bool) {
	session, ok := GetSessionFromContext(ctx)
	return session.Username, ok
}

type AuthMiddleware struct {
	jwtSecret []byte
}

// Se elimina user_service, la Base de Datos ya no es requerida aquí.
func NewAuthMiddleware(secret []byte) *AuthMiddleware {
	return &AuthMiddleware{jwtSecret: secret}
}

func (m *AuthMiddleware) RequireAuth() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenString, err := extractBearerToken(r.Header.Get("Authorization"))
			if err != nil {
				handlers.RespondError(w, http.StatusUnauthorized, err.Error())
				return
			}

			claims := jwt.MapClaims{}
			token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
				return m.jwtSecret, nil
			})

			if err != nil || !token.Valid {
				handlers.RespondError(w, http.StatusUnauthorized, "invalid or expired token")
				return
			}

			sub, ok := claims["sub"].(string)
			if !ok {
				handlers.RespondError(w, http.StatusUnauthorized, "invalid token payload")
				return
			}

			// Pre-calcular el mapa de permisos en memoria (O(1) lookups posteriores)
			permsMap := make(map[string]bool)
			if permsArr, ok := claims["permissions"].([]interface{}); ok {
				for _, p := range permsArr {
					if pStr, valid := p.(string); valid {
						permsMap[pStr] = true
					}
				}
			}

			session := UserSession{
				Username:    sub,
				Permissions: permsMap,
			}

			ctx := context.WithValue(r.Context(), userSessionKey, session)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (m *AuthMiddleware) RequirePermission(requiredPerm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, ok := GetSessionFromContext(r.Context())
			if !ok {
				handlers.RespondError(w, http.StatusUnauthorized, "unauthorized access context")
				return
			}

			// HOT PATH OPTIMIZADO: Look-up en memoria O(1). CERO base de datos.
			if !session.Permissions[requiredPerm] {
				handlers.RespondError(w, http.StatusForbidden, "forbidden: core-permission missing")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func extractBearerToken(authHeader string) (string, error) {
	if authHeader == "" {
		return "", errors.New("missing authorization header")
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", errors.New("invalid authorization token format")
	}
	return parts[1], nil
}
