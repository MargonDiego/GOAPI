package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
)

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
