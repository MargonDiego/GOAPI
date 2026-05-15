package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/diego/go-api/internal/application"
	"github.com/diego/go-api/internal/domain"
	"github.com/diego/go-api/internal/presentation/rest/middleware"
	"github.com/go-playground/validator/v10"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
)

var validate = validator.New()

// --- Envelope de respuesta unificado ---

// APIResponse es el wrapper estándar para TODAS las respuestas HTTP de la API.
// Garantiza consistencia en el contrato JSON para cualquier cliente.
type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
	Code    string      `json:"code,omitempty"` // Código de error de dominio (ej: "USER_NOT_FOUND")
	Meta    *APIMeta    `json:"meta,omitempty"`
}

// APIMeta contiene metadatos de paginación. nil = respuesta sin paginar.
type APIMeta struct {
	Page       int `json:"page,omitempty"`
	Size       int `json:"size,omitempty"`
	Total      int `json:"total,omitempty"`
	TotalPages int `json:"total_pages,omitempty"`
}

// --- Mapeo de errores de dominio a HTTP ---

// MapDomainError extrae el código HTTP de un AppError del dominio.
// Si el error no es un AppError (ej: error de BD, red), retorna 500.
// Usa errors.As para atravesar la cadena de wrapping (fmt.Errorf con %w).
func MapDomainError(err error) int {
	var appErr *domain.AppError
	if errors.As(err, &appErr) {
		return appErr.Status
	}
	return http.StatusInternalServerError
}

// DecodeAndValidate decodifica el body JSON en el DTO y ejecuta validación.
// Retorna un slice de mensajes de error si la validación falla.
func DecodeAndValidate(r *http.Request, dto interface{}) []string {
	if err := json.NewDecoder(r.Body).Decode(dto); err != nil {
		return []string{"invalid json payload"}
	}

	if err := validate.Struct(dto); err != nil {
		var errs []string
		for _, e := range err.(validator.ValidationErrors) {
			errs = append(errs, formatValidationError(e))
		}
		return errs
	}

	return nil
}

// formatValidationError traduce un error de validator a un mensaje legible.
func formatValidationError(e validator.FieldError) string {
	field := strings.ToLower(e.Field())
	switch e.Tag() {
	case "required":
		return field + " is required"
	case "min":
		return field + " must be at least " + e.Param() + " characters"
	case "max":
		return field + " must be at most " + e.Param() + " characters"
	case "email":
		return field + " must be a valid email address"
	default:
		return field + " failed validation: " + e.Tag()
	}
}

// RespondJSON serializa respuestas exitosas con el envelope unificado APIResponse.
func RespondJSON(w http.ResponseWriter, status int, data interface{}) {
	writeJSON(w, status, APIResponse{Success: true, Data: data})
}

// RespondError emite errores de cliente/servidor con el envelope unificado.
// Para errores de dominio con código, usar RenderError que incluye el campo "code".
func RespondError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, APIResponse{Success: false, Error: message})
}

// RespondPaginated serializa una respuesta paginada con metadatos en APIResponse.
func RespondPaginated(w http.ResponseWriter, data interface{}, page, size, total int) {
	meta := &APIMeta{
		Page:  page,
		Size:  size,
		Total: total,
	}
	if size > 0 {
		meta.TotalPages = total / size
		if total%size > 0 {
			meta.TotalPages++
		}
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: data, Meta: meta})
}

// RenderError extrae el AppError del dominio (si existe), lo loguea si es 5xx,
// y emite la respuesta con código de error y mensaje estructurado.
// Reemplaza el patrón repetitivo "if errors.Is(...) { RespondError(...) }" en cada handler.
func RenderError(w http.ResponseWriter, r *http.Request, err error) {
	var appErr *domain.AppError
	if errors.As(err, &appErr) {
		// Error de dominio conocido: incluye el campo "code" en la respuesta.
		writeJSON(w, appErr.Status, APIResponse{
			Success: false,
			Error:   appErr.Message,
			Code:    appErr.Code,
		})
		return
	}

	// Error inesperado (BD, red, etc.): 500 sin exponer detalles al cliente.
	log.Error().
		Err(err).
		Str("method", r.Method).
		Str("path", r.URL.Path).
		Str("request_id", middleware.GetRequestID(r.Context())).
		Msg("internal error")
	RespondError(w, http.StatusInternalServerError, "internal server error")
}

// RenderValidationError emite errores de validación con código 400.
func RenderValidationError(w http.ResponseWriter, errs []string) {
	writeJSON(w, http.StatusBadRequest, APIResponse{
		Success: false,
		Error:   "validation failed",
		Data:    errs,
	})
}

// writeJSON es el helper de más bajo nivel que escribe el JSON al wire.
// NUNCA debe llamarse fuera de este archivo — usar los helpers públicos.
func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Error().Err(err).Msg("failed to encode JSON response")
	}
}

// getIDFromURL extrae un ID entero positivo de los parámetros de ruta de mux.Router.
// Rechaza IDs <= 0 y valores no numéricos.
func getIDFromURL(r *http.Request, param string) (int, error) {
	vars := mux.Vars(r)
	idStr, ok := vars[param]
	if !ok {
		return 0, errors.New("parameter not found in URL")
	}
	id, err := strconv.Atoi(idStr)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", param, err)
	}
	if id <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer, got %d", param, id)
	}
	return id, nil
}

// withActor extrae el userID, scope, IP y User-Agent de la sesión/request y los inyecta en el contexto
// para que los servicios puedan registrar auditoría completa y aplicar scoping.
// Si no hay sesión, retorna el contexto original.
func withActor(r *http.Request) context.Context {
	ctx := r.Context()
	if session, ok := middleware.GetSessionFromContext(ctx); ok {
		ctx = application.WithActor(ctx, session.UserID)
		ctx = application.WithScope(ctx, session.Scope)
	}
	// Extraer IP real considerando proxies (X-Forwarded-For o X-Real-IP).
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.Header.Get("X-Real-Ip")
	}
	if ip == "" {
		ip = r.RemoteAddr
	}
	ctx = application.WithIP(ctx, ip)
	ctx = application.WithUserAgent(ctx, r.UserAgent())
	return ctx
}
