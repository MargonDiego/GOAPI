package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/diego/go-api/internal/application"
	"github.com/diego/go-api/internal/domain"
	"github.com/diego/go-api/internal/presentation/http/middleware"
)

// AuthRequest es el DTO de entrada para registro y login.
type AuthRequest struct {
	Username string `json:"username" example:"johndoe"`
	Password string `json:"password" example:"secret1234"`
	Email    string `json:"email,omitempty" example:"johndoe@example.com"` // Opcional. Se cifra con AES-256-GCM antes de persistir.
}

// RefreshRequest es el DTO para solicitar un nuevo token.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" example:"rand_base64_string"`
}

// AuthResponse es el DTO de respuesta para login exitoso.
type AuthResponse struct {
	AccessToken  string `json:"access_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	RefreshToken string `json:"refresh_token" example:"rand_base64_string"`
}

// MessageResponse es una respuesta genérica con mensaje.
type MessageResponse struct {
	Message string `json:"message" example:"user registered successfully"`
}

// ErrorResponse es una respuesta de error estándar.
type ErrorResponse struct {
	Error string `json:"error" example:"invalid credentials"`
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "invalid json payload")
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if req.Username == "" || req.Password == "" || req.Email == "" {
		RespondError(w, http.StatusBadRequest, "username, password and email are required")
		return
	}

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
// @Description  Autentica credenciales y retorna un token JWT con permisos embebidos
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "invalid json payload")
		return
	}

	accessToken, refreshToken, err := h.authService.Login(r.Context(), req.Username, req.Password)
	if err != nil {
		h.handleAuthError(w, err)
		return
	}

	RespondJSON(w, http.StatusOK, AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

// Refresh renueva el Access Token usando un Refresh Token válido.
//
// @Summary      Renovar sesión
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "invalid json payload")
		return
	}

	if req.RefreshToken == "" {
		RespondError(w, http.StatusBadRequest, "refresh_token is required")
		return
	}

	newAccess, newRefresh, err := h.authService.RefreshTokens(r.Context(), req.RefreshToken)
	if err != nil {
		// Retornar 401 si el refresh token es inválido/expirado, obliga al front a hacer relogin
		RespondError(w, http.StatusUnauthorized, "invalid or expired refresh token")
		return
	}

	RespondJSON(w, http.StatusOK, AuthResponse{
		AccessToken:  newAccess,
		RefreshToken: newRefresh,
	})
}

// Logout cierra la sesión del usuario.
//
// @Summary      Cerrar sesión
// @Description  Invalida todos los refresh tokens del usuario
// @Tags         auth
// @Accept       json
// @Produce      json
// @Success      200 {object} MessageResponse
// @Failure      401 {object} ErrorResponse
// @Failure      500 {object} ErrorResponse
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

	RespondJSON(w, http.StatusOK, MessageResponse{
		Message: "logged out successfully",
	})
}

// handleAuthError mapea errores del dominio/aplicación a códigos HTTP RESTful.
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
		RespondError(w, http.StatusInternalServerError, "internal server error")
	}
}
