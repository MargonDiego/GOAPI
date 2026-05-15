package handlers

// --- DTOs compartidos entre todos los handlers ---

// ErrorResponse es la respuesta estÃ¡ndar para errores controlados.
type ErrorResponse struct {
	Error string `json:"error" example:"invalid credentials"`
}

// MessageResponse es una respuesta genÃ©rica con mensaje informativo.
type MessageResponse struct {
	Message string `json:"message" example:"user registered successfully"`
}
