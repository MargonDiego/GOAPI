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
	"github.com/diego/go-api/internal/presentation/rest/middleware"
	"github.com/go-playground/validator/v10"
	"github.com/gorilla/mux"
)

var validate = validator.New()

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

// RespondJSON es un helper para serializar respuestas exitosas
func RespondJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		// En un sistema real con contexto, aquí se usaría el logger inyectado
		// para registrar la falla al escribir en el socket.
		http.Error(w, "internal encoding error", http.StatusInternalServerError)
	}
}

// RespondError es un helper estandarizado para emitir errores de cliente controlados
func RespondError(w http.ResponseWriter, status int, message string) {
	RespondJSON(w, status, map[string]string{"error": message})
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
