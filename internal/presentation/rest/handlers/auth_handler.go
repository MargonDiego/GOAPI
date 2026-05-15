package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/MargonDiego/GOAPI/internal/application"
	"github.com/MargonDiego/GOAPI/internal/domain"
	"github.com/MargonDiego/GOAPI/internal/presentation/rest/middleware"
	"github.com/rs/zerolog/log"
)

// AuthRequest es el DTO de entrada para registro y login.
type AuthRequest struct {
	Username string `json:"username" validate:"required,min=3,max=50" example:"johndoe"`
	Password string `json:"password" validate:"required,min=8,max=72" example:"secret1234"`
	Email    string `json:"email,omitempty" validate:"omitempty,email" example:"johndoe@example.com"`
}

// RefreshRequest es el DTO para solicitar un nuevo token.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required,min=1" example:"rand_base64_string"`
}

// AuthResponse es el DTO de respuesta para login exitoso.
type AuthResponse struct {
	AccessToken  string `json:"access_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	RefreshToken string `json:"refresh_token" example:"rand_base64_string"`
}

type AuthHandler struct {
	authService application.AuthService
}

func NewAuthHandler(s application.AuthService) *AuthHandler {
	return &AuthHandler{authService: s}
}

// Register registra un nuevo usuario.
//
// @Summary      Registro de usuario
// @Description  Crea un nuevo usuario con el rol User por defecto
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body body AuthRequest true "Credenciales del nuevo usuario"
// @Success      201 {object} MessageResponse
// @Failure      400 {object} ErrorResponse
// @Failure      409 {object} ErrorResponse
// @Failure      500 {object} ErrorResponse
// @Router       /register [post]
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req AuthRequest
	if errs := DecodeAndValidate(r, &req); len(errs) > 0 {
		RespondJSON(w, http.StatusBadRequest, map[string]interface{}{"errors": errs})
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	err := h.authService.Register(r.Context(), req.Username, req.Password, req.Email)
	if err != nil {
		h.handleAuthError(w, err)
		return
	}

	RespondJSON(w, http.StatusCreated, map[string]string{
		"message": "user registered successfully",
	})
}

// Login autentica un usuario y devuelve un JWT.
//
// @Summary      Login de usuario
// @Description  Autentica credenciales y retorna un token JWT con permisos embebidos.
// @Description  Setea cookie HttpOnly access_token (anti-XSS) + SameSite=Strict (anti-CSRF).
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body body AuthRequest true "Credenciales"
// @Success      200 {object} AuthResponse
// @Failure      400 {object} ErrorResponse
// @Failure      401 {object} ErrorResponse
// @Failure      429 {object} ErrorResponse
// @Failure      500 {object} ErrorResponse
// @Router       /login [post]
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req AuthRequest
	if errs := DecodeAndValidate(r, &req); len(errs) > 0 {
		RespondJSON(w, http.StatusBadRequest, map[string]interface{}{"errors": errs})
		return
	}

	accessToken, refreshToken, err := h.authService.Login(r.Context(), req.Username, req.Password)
	if err != nil {
		h.handleAuthError(w, err)
		return
	}

	// Setear cookie HttpOnly (protege contra XSS)
	setAccessTokenCookie(w, accessToken, r.TLS != nil)

	// Devolver refresh_token en JSON para que el frontend lo almacene
	// y lo use en el endpoint /refresh
	RespondJSON(w, http.StatusOK, AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

// Refresh renueva el Access Token usando un Refresh Token vÃ¡lido.
//
// @Summary      Renovar sesiÃ³n
// @Description  Emite un nuevo Access Token y rota el Refresh Token
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body body RefreshRequest true "Refresh Token actual"
// @Success      200 {object} AuthResponse
// @Failure      400 {object} ErrorResponse
// @Failure      401 {object} ErrorResponse
// @Failure      500 {object} ErrorResponse
// @Router       /refresh [post]
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest
	if errs := DecodeAndValidate(r, &req); len(errs) > 0 {
		RespondJSON(w, http.StatusBadRequest, map[string]interface{}{"errors": errs})
		return
	}

	newAccess, newRefresh, err := h.authService.RefreshTokens(r.Context(), req.RefreshToken)
	if err != nil {
		// Retornar 401 si el refresh token es invalido/expirado, obliga al front a hacer relogin
		RespondError(w, http.StatusUnauthorized, "invalid or expired refresh token")
		return
	}

	// Renovar cookie HttpOnly
	setAccessTokenCookie(w, newAccess, r.TLS != nil)

	RespondJSON(w, http.StatusOK, AuthResponse{
		AccessToken:  newAccess,
		RefreshToken: newRefresh,
	})
}

// Logout cierra la sesiÃ³n del usuario.
//
// @Summary      Cerrar sesiÃ³n
// @Description  Invalida todos los refresh tokens del usuario
// @Tags         auth
// @Accept       json
// @Produce      json
// @Success      200 {object} MessageResponse
// @Failure      401 {object} ErrorResponse
// @Failure      500 {object} ErrorResponse
// @Security     BearerAuth
// @Router       /logout [post]
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok || userID == 0 {
		RespondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	if err := h.authService.Logout(r.Context(), userID); err != nil {
		RespondError(w, http.StatusInternalServerError, "failed to logout")
		return
	}

	// Limpiar cookie de sesion
	clearAccessTokenCookie(w)

	RespondJSON(w, http.StatusOK, MessageResponse{
		Message: "logged out successfully",
	})
}

// handleAuthError mapea errores del dominio/aplicaciÃ³n a cÃ³digos HTTP RESTful.
// Mejora la legibilidad quitando estos "if err" de los bloques funcionales.
func (h *AuthHandler) handleAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrUserAlreadyExists):
		RespondError(w, http.StatusConflict, err.Error())
	case errors.Is(err, domain.ErrEmailAlreadyExists):
		RespondError(w, http.StatusConflict, err.Error())
	case errors.Is(err, domain.ErrInvalidInput):
		RespondError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, domain.ErrInvalidCreds):
		RespondError(w, http.StatusUnauthorized, err.Error())
	case errors.Is(err, domain.ErrAccountLocked):
		// 429 Too Many Requests comunica al cliente que debe esperar.
		RespondError(w, http.StatusTooManyRequests, err.Error())
	default:
		log.Error().Err(err).Msg("unexpected error in auth handler")
		RespondError(w, http.StatusInternalServerError, "internal server error")
	}
}
