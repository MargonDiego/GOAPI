package handlers

import (
	"net/http"

	"github.com/MargonDiego/GOAPI/internal/application"
)

type EstudianteResponse struct {
	ID     uint   `json:"id"`
	Rut    string `json:"rut"`
	Nombre string `json:"nombre"`
	Curso  string `json:"curso"`
}

type CreateEstudianteRequest struct {
	Rut    string `json:"rut" validate:"required" example:"12.345.678-5"`
	Nombre string `json:"nombre" validate:"required,min=2,max=120" example:"Juan Pérez"`
	Curso  string `json:"curso" validate:"required,min=1,max=50" example:"8°B"`
}

type UpdateEstudianteRequest struct {
	Nombre string `json:"nombre,omitempty" validate:"omitempty,min=2,max=120"`
	Curso  string `json:"curso,omitempty" validate:"omitempty,min=1,max=50"`
}

type EstudianteHandler struct {
	svc application.EstudianteService
}

func NewEstudianteHandler(s application.EstudianteService) *EstudianteHandler {
	return &EstudianteHandler{svc: s}
}

// Create crea un estudiante.
//
// @Summary      Crear estudiante
// @Description  Crea un estudiante (solo dato, no usuario). PII cifrada en reposo.
// @Tags         estudiantes
// @Accept       json
// @Produce      json
// @Param        body body CreateEstudianteRequest true "Datos del estudiante"
// @Security     BearerAuth
// @Success      201 {object} MessageResponse
// @Failure      400 {object} ErrorResponse
// @Failure      401 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
// @Failure      409 {object} ErrorResponse
// @Router       /estudiantes [post]
func (h *EstudianteHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req CreateEstudianteRequest
	if errs := DecodeAndValidate(r, &req); len(errs) > 0 {
		RenderValidationError(w, errs)
		return
	}
	if err := h.svc.Create(withActor(r), req.Rut, req.Nombre, req.Curso); err != nil {
		RenderError(w, r, err)
		return
	}
	RespondJSON(w, http.StatusCreated, MessageResponse{Message: "estudiante created successfully"})
}

// GetByID obtiene un estudiante por ID.
//
// @Summary      Obtener estudiante
// @Tags         estudiantes
// @Produce      json
// @Param        id path int true "Estudiante ID"
// @Security     BearerAuth
// @Success      200 {object} EstudianteResponse
// @Failure      400 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
// @Failure      404 {object} ErrorResponse
// @Router       /estudiantes/{id} [get]
func (h *EstudianteHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	id, err := getIDFromURL(r, "id")
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid estudiante id")
		return
	}
	d, err := h.svc.GetByID(withActor(r), uint(id))
	if err != nil {
		RenderError(w, r, err)
		return
	}
	RespondJSON(w, http.StatusOK, EstudianteResponse{ID: d.ID, Rut: d.Rut, Nombre: d.Nombre, Curso: d.Curso})
}

// Search lista estudiantes paginados, filtrables por curso.
//
// @Summary      Listar estudiantes
// @Tags         estudiantes
// @Produce      json
// @Param        page query int false "Página" default(1)
// @Param        size query int false "Tamaño" default(10)
// @Param        curso query string false "Filtrar por curso"
// @Security     BearerAuth
// @Success      200 {object} APIResponse
// @Failure      401 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
// @Router       /estudiantes [get]
func (h *EstudianteHandler) Search(w http.ResponseWriter, r *http.Request) {
	page := parseQueryInt(r, "page", 1)
	size := parseQueryInt(r, "size", 10)
	curso := r.URL.Query().Get("curso")

	result, err := h.svc.Search(withActor(r), curso, page, size)
	if err != nil {
		RenderError(w, r, err)
		return
	}
	resp := make([]EstudianteResponse, 0, len(result.Data))
	for _, d := range result.Data {
		resp = append(resp, EstudianteResponse{ID: d.ID, Rut: d.Rut, Nombre: d.Nombre, Curso: d.Curso})
	}
	RespondPaginated(w, resp, result.Page, result.Size, result.Total)
}

// Update actualiza nombre/curso de un estudiante.
//
// @Summary      Actualizar estudiante
// @Tags         estudiantes
// @Accept       json
// @Produce      json
// @Param        id path int true "Estudiante ID"
// @Param        body body UpdateEstudianteRequest true "Datos a actualizar"
// @Security     BearerAuth
// @Success      200 {object} MessageResponse
// @Failure      400 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
// @Failure      404 {object} ErrorResponse
// @Router       /estudiantes/{id} [put]
func (h *EstudianteHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := getIDFromURL(r, "id")
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid estudiante id")
		return
	}
	var req UpdateEstudianteRequest
	if errs := DecodeAndValidate(r, &req); len(errs) > 0 {
		RenderValidationError(w, errs)
		return
	}
	if req.Nombre == "" && req.Curso == "" {
		RespondError(w, http.StatusBadRequest, "at least one field to update is required")
		return
	}
	if err := h.svc.UpdateDatos(withActor(r), uint(id), req.Nombre, req.Curso); err != nil {
		RenderError(w, r, err)
		return
	}
	RespondJSON(w, http.StatusOK, MessageResponse{Message: "estudiante updated successfully"})
}

// Delete elimina (soft) un estudiante.
//
// @Summary      Eliminar estudiante
// @Tags         estudiantes
// @Produce      json
// @Param        id path int true "Estudiante ID"
// @Security     BearerAuth
// @Success      200 {object} MessageResponse
// @Failure      400 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
// @Failure      404 {object} ErrorResponse
// @Router       /estudiantes/{id} [delete]
func (h *EstudianteHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := getIDFromURL(r, "id")
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid estudiante id")
		return
	}
	if err := h.svc.Delete(withActor(r), uint(id)); err != nil {
		RenderError(w, r, err)
		return
	}
	RespondJSON(w, http.StatusOK, MessageResponse{Message: "estudiante deleted successfully"})
}

// Restore recupera un estudiante soft-deleted.
//
// @Summary      Restaurar estudiante
// @Tags         estudiantes
// @Produce      json
// @Param        id path int true "Estudiante ID"
// @Security     BearerAuth
// @Success      200 {object} MessageResponse
// @Failure      400 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
// @Failure      404 {object} ErrorResponse
// @Router       /estudiantes/{id}/restore [post]
func (h *EstudianteHandler) Restore(w http.ResponseWriter, r *http.Request) {
	id, err := getIDFromURL(r, "id")
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid estudiante id")
		return
	}
	if err := h.svc.Restore(withActor(r), uint(id)); err != nil {
		RenderError(w, r, err)
		return
	}
	RespondJSON(w, http.StatusOK, MessageResponse{Message: "estudiante restored successfully"})
}
