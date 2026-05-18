package handlers

import (
	"net/http"
	"time"

	"github.com/MargonDiego/GOAPI/internal/application"
	"github.com/MargonDiego/GOAPI/internal/domain"
)

// --- DTOs ---

type IncidenciaResponse struct {
	ID                   uint   `json:"id"`
	Codigo               string `json:"codigo"`
	Titulo               string `json:"titulo"`
	Descripcion          string `json:"descripcion"`
	Gravedad             string `json:"gravedad"`
	Categoria            string `json:"categoria"`
	Estado               string `json:"estado"`
	EstudianteID         uint   `json:"estudiante_id"`
	DenuncianteID        uint   `json:"denunciante_id"`
	ResponsableID        *uint  `json:"responsable_id,omitempty"`
	Scope                string `json:"scope"`
	EsConstitutivoDeDelito bool   `json:"es_constitutivo_de_delito"`
	SuspensionPreventiva bool   `json:"suspension_preventiva"`
}

type CreateIncidenciaRequest struct {
	EstudianteID uint   `json:"estudiante_id"  validate:"required"`
	Titulo       string `json:"titulo"         validate:"required,min=3,max=200"`
	Descripcion  string `json:"descripcion"    validate:"required"`
	Gravedad     string `json:"gravedad"       validate:"required,oneof=LEVE GRAVE GRAVISIMA"`
	Categoria    string `json:"categoria"      validate:"required"`
	EsDelito     bool   `json:"es_constitutivo_de_delito"`
}

type AgregarComentarioRequest struct {
	Cuerpo string `json:"cuerpo" validate:"required,min=1"`
}

type AsignarRequest struct {
	ResponsableID uint `json:"responsable_id" validate:"required"`
}

type ResolverRequest struct {
	Fundamentacion string `json:"fundamentacion" validate:"required,min=10"`
	Decision       string `json:"decision"       validate:"required,min=5"`
}

type PresentarApelacionRequest struct {
	ResolucionID     uint      `json:"resolucion_id"     validate:"required"`
	Motivo           string    `json:"motivo"            validate:"required,min=10"`
	PlazoVencimiento time.Time `json:"plazo_vencimiento" validate:"required"`
}

type ResolverApelacionRequest struct {
	Fundamentacion string `json:"fundamentacion" validate:"required,min=10"`
	Decision       string `json:"decision"       validate:"required,min=5"`
	Aceptada       bool   `json:"aceptada"`
}

// --- Handler ---

type IncidenciaHandler struct {
	svc application.IncidenciaService
}

func NewIncidenciaHandler(s application.IncidenciaService) *IncidenciaHandler {
	return &IncidenciaHandler{svc: s}
}

func toIncidenciaResponse(i *domain.Incidencia) IncidenciaResponse {
	return IncidenciaResponse{
		ID:                   i.ID,
		Codigo:               i.Codigo,
		Titulo:               i.Titulo,
		Descripcion:          i.Descripcion,
		Gravedad:             string(i.Gravedad),
		Categoria:            string(i.Categoria),
		Estado:               string(i.Estado),
		EstudianteID:         i.EstudianteID,
		DenuncianteID:        i.DenuncianteID,
		ResponsableID:        i.ResponsableID,
		Scope:                i.Scope,
		EsConstitutivoDeDelito: i.EsConstitutivoDeDelito,
		SuspensionPreventiva: i.SuspensionPreventiva,
	}
}

// Create crea una incidencia de convivencia.
//
// @Summary      Crear incidencia
// @Description  Registra una incidencia de convivencia escolar según Ley 20.536.
// @Tags         incidencias
// @Accept       json
// @Produce      json
// @Param        body body CreateIncidenciaRequest true "Datos de la incidencia"
// @Security     BearerAuth
// @Success      201 {object} IncidenciaResponse
// @Failure      400 {object} ErrorResponse
// @Failure      401 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
// @Router       /incidencias [post]
func (h *IncidenciaHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req CreateIncidenciaRequest
	if errs := DecodeAndValidate(r, &req); len(errs) > 0 {
		RenderValidationError(w, errs)
		return
	}
	inc, err := h.svc.Crear(withActor(r), req.EstudianteID, req.Titulo, req.Descripcion,
		domain.GravedadIncidencia(req.Gravedad), domain.CategoriaIncidencia(req.Categoria), req.EsDelito)
	if err != nil {
		RenderError(w, r, err)
		return
	}
	RespondJSON(w, http.StatusCreated, toIncidenciaResponse(inc))
}

// GetByID obtiene una incidencia por ID.
//
// @Summary      Obtener incidencia
// @Tags         incidencias
// @Produce      json
// @Param        id path int true "Incidencia ID"
// @Security     BearerAuth
// @Success      200 {object} IncidenciaResponse
// @Failure      404 {object} ErrorResponse
// @Router       /incidencias/{id} [get]
func (h *IncidenciaHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	id, err := getIDFromURL(r, "id")
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid incidencia id")
		return
	}
	inc, err := h.svc.GetByID(withActor(r), uint(id))
	if err != nil {
		RenderError(w, r, err)
		return
	}
	RespondJSON(w, http.StatusOK, toIncidenciaResponse(inc))
}

// Search lista incidencias paginadas con filtros opcionales.
//
// @Summary      Listar incidencias
// @Tags         incidencias
// @Produce      json
// @Param        page         query int    false "Página"    default(1)
// @Param        size         query int    false "Tamaño"    default(10)
// @Param        estado       query string false "Estado"
// @Param        gravedad     query string false "Gravedad"
// @Param        categoria    query string false "Categoría"
// @Security     BearerAuth
// @Success      200 {object} APIResponse
// @Failure      401 {object} ErrorResponse
// @Router       /incidencias [get]
func (h *IncidenciaHandler) Search(w http.ResponseWriter, r *http.Request) {
	page := parseQueryInt(r, "page", 1)
	size := parseQueryInt(r, "size", 10)

	f := domain.IncidenciaFilter{
		Estado:    domain.EstadoIncidencia(r.URL.Query().Get("estado")),
		Gravedad:  domain.GravedadIncidencia(r.URL.Query().Get("gravedad")),
		Categoria: domain.CategoriaIncidencia(r.URL.Query().Get("categoria")),
	}

	result, err := h.svc.Search(withActor(r), f, page, size)
	if err != nil {
		RenderError(w, r, err)
		return
	}
	resp := make([]IncidenciaResponse, 0, len(result.Data))
	for i := range result.Data {
		resp = append(resp, toIncidenciaResponse(&result.Data[i]))
	}
	RespondPaginated(w, resp, result.Page, result.Size, int(result.Total))
}

// AddComentario agrega un comentario a una incidencia.
//
// @Summary      Agregar comentario
// @Tags         incidencias
// @Accept       json
// @Produce      json
// @Param        id   path int                      true "Incidencia ID"
// @Param        body body AgregarComentarioRequest true "Comentario"
// @Security     BearerAuth
// @Success      201 {object} MessageResponse
// @Failure      400 {object} ErrorResponse
// @Failure      404 {object} ErrorResponse
// @Router       /incidencias/{id}/comentarios [post]
func (h *IncidenciaHandler) AddComentario(w http.ResponseWriter, r *http.Request) {
	id, err := getIDFromURL(r, "id")
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid incidencia id")
		return
	}
	var req AgregarComentarioRequest
	if errs := DecodeAndValidate(r, &req); len(errs) > 0 {
		RenderValidationError(w, errs)
		return
	}
	if err := h.svc.AgregarComentario(withActor(r), uint(id), req.Cuerpo); err != nil {
		RenderError(w, r, err)
		return
	}
	RespondJSON(w, http.StatusCreated, MessageResponse{Message: "comentario agregado"})
}

// Asignar asigna un responsable a la incidencia.
//
// @Summary      Asignar responsable
// @Tags         incidencias
// @Accept       json
// @Produce      json
// @Param        id   path int           true "Incidencia ID"
// @Param        body body AsignarRequest true "Responsable"
// @Security     BearerAuth
// @Success      200 {object} MessageResponse
// @Failure      400 {object} ErrorResponse
// @Failure      404 {object} ErrorResponse
// @Router       /incidencias/{id}/asignar [post]
func (h *IncidenciaHandler) Asignar(w http.ResponseWriter, r *http.Request) {
	id, err := getIDFromURL(r, "id")
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid incidencia id")
		return
	}
	var req AsignarRequest
	if errs := DecodeAndValidate(r, &req); len(errs) > 0 {
		RenderValidationError(w, errs)
		return
	}
	if err := h.svc.Asignar(withActor(r), uint(id), req.ResponsableID); err != nil {
		RenderError(w, r, err)
		return
	}
	RespondJSON(w, http.StatusOK, MessageResponse{Message: "responsable asignado"})
}

// IniciarInvestigacion transiciona la incidencia a EN_INVESTIGACION.
//
// @Summary      Iniciar investigación
// @Tags         incidencias
// @Produce      json
// @Param        id path int true "Incidencia ID"
// @Security     BearerAuth
// @Success      200 {object} MessageResponse
// @Failure      404 {object} ErrorResponse
// @Failure      409 {object} ErrorResponse
// @Router       /incidencias/{id}/investigar [post]
func (h *IncidenciaHandler) IniciarInvestigacion(w http.ResponseWriter, r *http.Request) {
	id, err := getIDFromURL(r, "id")
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid incidencia id")
		return
	}
	if err := h.svc.IniciarInvestigacion(withActor(r), uint(id), time.Now()); err != nil {
		RenderError(w, r, err)
		return
	}
	RespondJSON(w, http.StatusOK, MessageResponse{Message: "investigación iniciada"})
}

// Resolver emite la resolución de una incidencia.
//
// @Summary      Resolver incidencia
// @Tags         incidencias
// @Accept       json
// @Produce      json
// @Param        id   path int            true "Incidencia ID"
// @Param        body body ResolverRequest true "Resolución"
// @Security     BearerAuth
// @Success      200 {object} MessageResponse
// @Failure      400 {object} ErrorResponse
// @Failure      404 {object} ErrorResponse
// @Failure      409 {object} ErrorResponse
// @Router       /incidencias/{id}/resolver [post]
func (h *IncidenciaHandler) Resolver(w http.ResponseWriter, r *http.Request) {
	id, err := getIDFromURL(r, "id")
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid incidencia id")
		return
	}
	var req ResolverRequest
	if errs := DecodeAndValidate(r, &req); len(errs) > 0 {
		RenderValidationError(w, errs)
		return
	}
	if err := h.svc.Resolver(withActor(r), uint(id), req.Fundamentacion, req.Decision); err != nil {
		RenderError(w, r, err)
		return
	}
	RespondJSON(w, http.StatusOK, MessageResponse{Message: "incidencia resuelta"})
}

// PresentarApelacion presenta una apelación a la resolución.
//
// @Summary      Presentar apelación
// @Tags         incidencias
// @Accept       json
// @Produce      json
// @Param        id   path int                       true "Incidencia ID"
// @Param        body body PresentarApelacionRequest true "Apelación"
// @Security     BearerAuth
// @Success      201 {object} MessageResponse
// @Failure      400 {object} ErrorResponse
// @Failure      404 {object} ErrorResponse
// @Failure      409 {object} ErrorResponse
// @Router       /incidencias/{id}/apelar [post]
func (h *IncidenciaHandler) PresentarApelacion(w http.ResponseWriter, r *http.Request) {
	id, err := getIDFromURL(r, "id")
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid incidencia id")
		return
	}
	var req PresentarApelacionRequest
	if errs := DecodeAndValidate(r, &req); len(errs) > 0 {
		RenderValidationError(w, errs)
		return
	}
	if err := h.svc.PresentarApelacion(withActor(r), uint(id), req.ResolucionID, req.Motivo, req.PlazoVencimiento); err != nil {
		RenderError(w, r, err)
		return
	}
	RespondJSON(w, http.StatusCreated, MessageResponse{Message: "apelación presentada"})
}

// ResolverApelacion resuelve una apelación pendiente.
//
// @Summary      Resolver apelación
// @Tags         incidencias
// @Accept       json
// @Produce      json
// @Param        id          path int                      true "Incidencia ID"
// @Param        apelacion   path int                      true "Apelación ID"
// @Param        body        body ResolverApelacionRequest true "Resolución de apelación"
// @Security     BearerAuth
// @Success      200 {object} MessageResponse
// @Failure      400 {object} ErrorResponse
// @Failure      404 {object} ErrorResponse
// @Router       /incidencias/{id}/apelaciones/{apelacion}/resolver [post]
func (h *IncidenciaHandler) ResolverApelacion(w http.ResponseWriter, r *http.Request) {
	apelacionID, err := getIDFromURL(r, "apelacion")
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid apelacion id")
		return
	}
	var req ResolverApelacionRequest
	if errs := DecodeAndValidate(r, &req); len(errs) > 0 {
		RenderValidationError(w, errs)
		return
	}
	if err := h.svc.ResolverApelacion(withActor(r), uint(apelacionID), req.Fundamentacion, req.Decision, req.Aceptada); err != nil {
		RenderError(w, r, err)
		return
	}
	RespondJSON(w, http.StatusOK, MessageResponse{Message: "apelación resuelta"})
}

// Cerrar cierra una incidencia.
//
// @Summary      Cerrar incidencia
// @Tags         incidencias
// @Produce      json
// @Param        id path int true "Incidencia ID"
// @Security     BearerAuth
// @Success      200 {object} MessageResponse
// @Failure      404 {object} ErrorResponse
// @Failure      409 {object} ErrorResponse
// @Router       /incidencias/{id}/cerrar [post]
func (h *IncidenciaHandler) Cerrar(w http.ResponseWriter, r *http.Request) {
	id, err := getIDFromURL(r, "id")
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid incidencia id")
		return
	}
	if err := h.svc.Cerrar(withActor(r), uint(id)); err != nil {
		RenderError(w, r, err)
		return
	}
	RespondJSON(w, http.StatusOK, MessageResponse{Message: "incidencia cerrada"})
}

// GetExpediente obtiene el expediente completo de una incidencia.
//
// @Summary      Obtener expediente
// @Tags         incidencias
// @Produce      json
// @Param        id path int true "Incidencia ID"
// @Security     BearerAuth
// @Success      200 {object} application.Expediente
// @Failure      404 {object} ErrorResponse
// @Router       /incidencias/{id}/expediente [get]
func (h *IncidenciaHandler) GetExpediente(w http.ResponseWriter, r *http.Request) {
	id, err := getIDFromURL(r, "id")
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid incidencia id")
		return
	}
	exp, err := h.svc.GetExpediente(withActor(r), uint(id))
	if err != nil {
		RenderError(w, r, err)
		return
	}
	RespondJSON(w, http.StatusOK, exp)
}
