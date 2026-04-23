package handlers

import (
	"encoding/json"
	"net/http"
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
