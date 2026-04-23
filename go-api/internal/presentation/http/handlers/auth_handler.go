package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/diego/go-api/internal/application"
	"github.com/diego/go-api/internal/domain"
)

type AuthRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AuthHandler struct {
	authService application.AuthService
}

func NewAuthHandler(s application.AuthService) *AuthHandler {
	return &AuthHandler{authService: s}
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	// MITIGACIÓN DOS: Limitar payload a 10KB para evitar OOM y agotamiento por parsing.
	r.Body = http.MaxBytesReader(w, r.Body, 1024*10)

	var req AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusRequestEntityTooLarge, "payload too large or invalid json")
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		RespondError(w, http.StatusBadRequest, "username and password are required")
		return
	}

	err := h.authService.Register(r.Context(), req.Username, req.Password)
	if err != nil {
		h.handleAuthError(w, err)
		return
	}

	RespondJSON(w, http.StatusCreated, map[string]string{
		"message": "user registered successfully",
	})
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	// MITIGACIÓN DOS: Limitar payload a 10KB
	r.Body = http.MaxBytesReader(w, r.Body, 1024*10)

	var req AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusRequestEntityTooLarge, "payload too large or invalid json")
		return
	}

	token, err := h.authService.Login(r.Context(), req.Username, req.Password)
	if err != nil {
		h.handleAuthError(w, err)
		return
	}

	RespondJSON(w, http.StatusOK, map[string]string{
		"token": token,
	})
}

func (h *AuthHandler) handleAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrUserAlreadyExists):
		RespondError(w, http.StatusConflict, err.Error())
	case errors.Is(err, domain.ErrInvalidInput):
		RespondError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, domain.ErrInvalidCreds):
		RespondError(w, http.StatusUnauthorized, err.Error())
	default:
		// Se ocultan errores internos explícitamente para evitar exfiltración
		RespondError(w, http.StatusInternalServerError, "internal server error")
	}
}
