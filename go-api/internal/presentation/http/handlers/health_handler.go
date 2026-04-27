package handlers

import (
	"context"
	"net/http"
)

// DatabasePinger define el contrato para verificar la salud de la BD.
// Esto permite mockearlo en tests sin acoplarse a GORM o sql.DB directamente.
type DatabasePinger interface {
	PingContext(ctx context.Context) error
}

type HealthHandler struct {
	db DatabasePinger
}

func NewHealthHandler(db DatabasePinger) *HealthHandler {
	return &HealthHandler{db: db}
}

// Liveness verifica que la aplicación esté corriendo (que el binario responda peticiones).
func (h *HealthHandler) Liveness(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// Readiness verifica que la aplicación esté lista para recibir tráfico (ej. la BD funciona).
func (h *HealthHandler) Readiness(w http.ResponseWriter, r *http.Request) {
	if h.db != nil {
		if err := h.db.PingContext(r.Context()); err != nil {
			http.Error(w, "Database Unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("READY"))
}
