package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/diego/go-api/internal/domain"
	"github.com/diego/go-api/internal/infrastructure/cache"
	"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const userSessionKey contextKey = "user_session"
const userIDKey contextKey = "user_id"

// UserSession almacena los datos extraídos del JWT en memoria (cero I/O en handlers).
type UserSession struct {
	Username    string
	Permissions map[string]bool
	UserID      uint
}

func GetSessionFromContext(ctx context.Context) (UserSession, bool) {
	session, ok := ctx.Value(userSessionKey).(UserSession)
	return session, ok
}

// ContextWithSession inyecta una UserSession en el contexto (útil para tests).
func ContextWithSession(ctx context.Context, session UserSession) context.Context {
	return context.WithValue(ctx, userSessionKey, session)
}

// GetUsernameFromContext se mantiene por retrocompatibilidad con handlers existentes.
func GetUsernameFromContext(ctx context.Context) (string, bool) {
	session, ok := GetSessionFromContext(ctx)
	return session.Username, ok
}

func GetUserIDFromContext(ctx context.Context) (uint, bool) {
	id, ok := ctx.Value(userIDKey).(uint)
	return id, ok
}

// AuthMiddleware valida JWT y verifica que token_version no haya sido invalidada.
//
// Solución al problema de stale Fat JWT:
//   - El JWT embebe "ver" = token_version del usuario al momento del login.
//   - Cuando un admin cambia los roles/permisos de un usuario, se incrementa token_version en DB.
//   - Este middleware compara JWT.ver con DB.token_version en cada request autenticado.
//   - Si no coinciden → 401, el usuario debe re-autenticarse para obtener un JWT actualizado.
//
// Rendimiento:
//   - El check usa un cache en memoria con TTL de 30s → cero accesos a Postgres en el caso feliz.
//   - En invalidación explícita (AssignRoles/AssignPermissions), el cache se limpia inmediatamente.
//   - La ventana máxima de stale permissions pasa de 15 min (TTL del JWT) a 30s (TTL del cache).
type AuthMiddleware struct {
	jwtSecret    []byte
	userRepo     domain.UserRepository
	versionCache *cache.TokenVersionCache
}

// NewAuthMiddleware construye el middleware con sus dependencias inyectadas.
func NewAuthMiddleware(secret []byte, userRepo domain.UserRepository, versionCache *cache.TokenVersionCache) *AuthMiddleware {
	return &AuthMiddleware{
		jwtSecret:    secret,
		userRepo:     userRepo,
		versionCache: versionCache,
	}
}

// respondError es local para evitar el ciclo de importación circular con /handlers.
func respondError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// RequireAuth valida el JWT y verifica que su token_version coincida con la versión actual.
//
// Flujo por request:
//  1. Extraer y parsear el Bearer token (firma HMAC-SHA256).
//  2. Leer claims: sub, uid, ver, permissions.
//  3. Validar token_version: cache hit → O(1), cache miss → SELECT + cache fill.
//  4. Si JWT.ver != currentVersion → 401 (permisos revocados, re-login requerido).
//  5. Inyectar UserSession en el contexto para los handlers downstream.
func (m *AuthMiddleware) RequireAuth() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenString, err := extractBearerToken(r.Header.Get("Authorization"))
			if err != nil {
				respondError(w, http.StatusUnauthorized, err.Error())
				return
			}

			claims := jwt.MapClaims{}
			token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				return m.jwtSecret, nil
			})

			if err != nil || !token.Valid {
				respondError(w, http.StatusUnauthorized, "invalid or expired token")
				return
			}

			sub, ok := claims["sub"].(string)
			if !ok {
				respondError(w, http.StatusUnauthorized, "invalid token payload")
				return
			}

			uid, _ := claims["uid"].(float64)
			userID := uint(uid)

			// Validar token_version: detecta si los permisos cambiaron tras emitir el token.
			if err := m.validateTokenVersion(r.Context(), userID, claims); err != nil {
				if errors.Is(err, domain.ErrUserNotFound) {
					respondError(w, http.StatusUnauthorized, "user not found")
					return
				}
				respondError(w, http.StatusUnauthorized, "token revoked: please log in again")
				return
			}

			// Pre-calcular el mapa de permisos en memoria (O(1) en RequirePermission).
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
				UserID:      userID,
				Permissions: permsMap,
			}

			ctx := context.WithValue(r.Context(), userSessionKey, session)
			ctx = context.WithValue(ctx, userIDKey, userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// validateTokenVersion compara el claim "ver" del JWT con la versión actual del usuario.
// Estrategia cache-aside:
//   - Cache hit  → comparación local, sin DB (caso mayoría de requests).
//   - Cache miss → lectura de Postgres + populate cache para futuros requests.
//
// Cuando AssignRolesToUser o AssignPermissionsToRole modifican un usuario,
// el caller llama a versionCache.Invalidate(userID) para forzar re-lectura inmediata.
func (m *AuthMiddleware) validateTokenVersion(ctx context.Context, userID uint, claims jwt.MapClaims) error {
	// 1. Intentar resolución desde cache.
	currentVersion, cached := m.versionCache.Get(userID)
	if !cached {
		// 2. Cache miss: leer desde Postgres y cachear para futuros requests.
		var err error
		currentVersion, err = m.userRepo.GetTokenVersion(ctx, userID)
		if err != nil {
			return err
		}
		m.versionCache.Set(userID, currentVersion)
	}

	// 3. Extraer versión del JWT. Tokens sin claim "ver" (legacy) se rechazan.
	verClaim, ok := claims["ver"].(float64)
	if !ok {
		return fmt.Errorf("missing or invalid ver claim")
	}
	tokenVersion := int(verClaim)

	// 4. Comparar: si no coinciden, los permisos fueron revocados tras emitir este token.
	if tokenVersion != currentVersion {
		return fmt.Errorf("token version mismatch: token=%d current=%d", tokenVersion, currentVersion)
	}
	return nil
}

// RequirePermission verifica que la sesión incluya el permiso requerido.
// HOT PATH: lookup en mapa en memoria — CERO accesos a base de datos.
func (m *AuthMiddleware) RequirePermission(requiredPerm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, ok := GetSessionFromContext(r.Context())
			if !ok {
				respondError(w, http.StatusUnauthorized, "unauthorized access context")
				return
			}

			if !session.Permissions[requiredPerm] {
				respondError(w, http.StatusForbidden, "forbidden: required permission missing")
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
