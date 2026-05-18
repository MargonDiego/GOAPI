package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MargonDiego/GOAPI/internal/application"
	"github.com/MargonDiego/GOAPI/internal/domain"
	"github.com/MargonDiego/GOAPI/internal/presentation/rest/handlers"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeIncidenciaService implementa application.IncidenciaService para tests de handler.
type fakeIncidenciaService struct {
	crearResult   *domain.Incidencia
	crearErr      error
	getByIDResult *domain.Incidencia
	getByIDErr    error
	comentarioErr error
	investigarErr error
	resolverErr   error
	cerrarErr     error
	asignarErr    error
	apelarErr     error
	searchResult  domain.PaginatedResult[domain.Incidencia]
	searchErr     error
	expediente    *application.Expediente
	expedienteErr error
}

func (f *fakeIncidenciaService) Crear(_ context.Context, _ uint, _, _ string, _ domain.GravedadIncidencia, _ domain.CategoriaIncidencia, _ bool) (*domain.Incidencia, error) {
	return f.crearResult, f.crearErr
}
func (f *fakeIncidenciaService) Asignar(_ context.Context, _, _ uint) error { return f.asignarErr }
func (f *fakeIncidenciaService) IniciarInvestigacion(_ context.Context, _ uint, _ time.Time) error {
	return f.investigarErr
}
func (f *fakeIncidenciaService) AgregarComentario(_ context.Context, _ uint, _ string) error {
	return f.comentarioErr
}
func (f *fakeIncidenciaService) AdjuntarArchivo(_ context.Context, _ uint, _ io.Reader, _ domain.FileMeta) (*domain.Adjunto, error) {
	return nil, nil
}
func (f *fakeIncidenciaService) RegistrarDescargo(_ context.Context, _ uint, _ string) error {
	return nil
}
func (f *fakeIncidenciaService) RegistrarMedida(_ context.Context, _ uint, _ domain.ClaseMedida, _ domain.TipoMedida, _, _ string, _ uint, _ time.Time, _ *time.Time) error {
	return nil
}
func (f *fakeIncidenciaService) Resolver(_ context.Context, _ uint, _, _ string) error {
	return f.resolverErr
}
func (f *fakeIncidenciaService) RegistrarNotificacion(_ context.Context, _ uint, _, _, _ string, _ time.Time) error {
	return nil
}
func (f *fakeIncidenciaService) PresentarApelacion(_ context.Context, _, _ uint, _ string, _ time.Time) error {
	return f.apelarErr
}
func (f *fakeIncidenciaService) ResolverApelacion(_ context.Context, _ uint, _, _ string, _ bool) error {
	return nil
}
func (f *fakeIncidenciaService) Derivar(_ context.Context, _ uint) error          { return nil }
func (f *fakeIncidenciaService) IniciarSeguimiento(_ context.Context, _ uint) error { return nil }
func (f *fakeIncidenciaService) Cerrar(_ context.Context, _ uint) error           { return f.cerrarErr }
func (f *fakeIncidenciaService) ObtenerAdjunto(_ context.Context, _ uint) (*domain.Adjunto, io.ReadCloser, error) {
	return nil, nil, nil
}
func (f *fakeIncidenciaService) GetByID(_ context.Context, _ uint) (*domain.Incidencia, error) {
	return f.getByIDResult, f.getByIDErr
}
func (f *fakeIncidenciaService) Search(_ context.Context, _ domain.IncidenciaFilter, _, _ int) (domain.PaginatedResult[domain.Incidencia], error) {
	return f.searchResult, f.searchErr
}
func (f *fakeIncidenciaService) ConfirmarAcuseNotificacion(_ context.Context, _ uint) error {
	return nil
}
func (f *fakeIncidenciaService) GetExpediente(_ context.Context, _ uint) (*application.Expediente, error) {
	return f.expediente, f.expedienteErr
}

// helpers
func newIncidenciaWithID(id uint) *domain.Incidencia {
	inc, _ := domain.NewIncidencia("Pelea en patio", "desc", domain.GravedadGrave, domain.CategoriaMaltratoEstudiantes, 1, 1, "colegio-a")
	inc.ID = id
	inc.Codigo = "INC-2026-0001"
	return inc
}

func withMuxVar(r *http.Request, key, value string) *http.Request {
	return mux.SetURLVars(r, map[string]string{key: value})
}

// --- Tests ---

func TestIncidenciaHandler_Create_OK(t *testing.T) {
	t.Parallel()
	inc := newIncidenciaWithID(1)
	h := handlers.NewIncidenciaHandler(&fakeIncidenciaService{crearResult: inc})

	body, _ := json.Marshal(map[string]interface{}{
		"estudiante_id": 1,
		"titulo":        "Pelea en patio",
		"descripcion":   "descripción detallada",
		"gravedad":      "GRAVE",
		"categoria":     "MALTRATO_ESTUDIANTES",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/incidencias", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.Create(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)
	var resp handlers.APIResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.True(t, resp.Success)
}

func TestIncidenciaHandler_Create_Validation(t *testing.T) {
	t.Parallel()
	h := handlers.NewIncidenciaHandler(&fakeIncidenciaService{})

	// titulo vacío
	body, _ := json.Marshal(map[string]interface{}{
		"estudiante_id": 1,
		"titulo":        "",
		"descripcion":   "desc",
		"gravedad":      "GRAVE",
		"categoria":     "MALTRATO_ESTUDIANTES",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/incidencias", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.Create(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestIncidenciaHandler_Create_ServiceError(t *testing.T) {
	t.Parallel()
	h := handlers.NewIncidenciaHandler(&fakeIncidenciaService{crearErr: domain.ErrTransicionInvalida})
	body, _ := json.Marshal(map[string]interface{}{
		"estudiante_id": 1,
		"titulo":        "Pelea",
		"descripcion":   "desc",
		"gravedad":      "GRAVE",
		"categoria":     "MALTRATO_ESTUDIANTES",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/incidencias", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.Create(rec, req)

	assert.Equal(t, http.StatusConflict, rec.Code)
}

func TestIncidenciaHandler_GetByID_OK(t *testing.T) {
	t.Parallel()
	inc := newIncidenciaWithID(42)
	h := handlers.NewIncidenciaHandler(&fakeIncidenciaService{getByIDResult: inc})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidencias/42", nil)
	req = withMuxVar(req, "id", "42")
	rec := httptest.NewRecorder()

	h.GetByID(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestIncidenciaHandler_GetByID_NotFound(t *testing.T) {
	t.Parallel()
	h := handlers.NewIncidenciaHandler(&fakeIncidenciaService{getByIDErr: domain.ErrIncidenciaNotFound})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidencias/99", nil)
	req = withMuxVar(req, "id", "99")
	rec := httptest.NewRecorder()

	h.GetByID(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestIncidenciaHandler_Search_OK(t *testing.T) {
	t.Parallel()
	inc := newIncidenciaWithID(1)
	result := domain.PaginatedResult[domain.Incidencia]{
		Data: []domain.Incidencia{*inc}, Total: 1, Page: 1, Size: 10,
	}
	h := handlers.NewIncidenciaHandler(&fakeIncidenciaService{searchResult: result})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidencias?page=1&size=10", nil)
	rec := httptest.NewRecorder()

	h.Search(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp handlers.APIResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.NotNil(t, resp.Meta)
}

func TestIncidenciaHandler_AddComentario_OK(t *testing.T) {
	t.Parallel()
	h := handlers.NewIncidenciaHandler(&fakeIncidenciaService{})

	body, _ := json.Marshal(map[string]string{"cuerpo": "comentario de prueba"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/incidencias/1/comentarios", bytes.NewReader(body))
	req = withMuxVar(req, "id", "1")
	rec := httptest.NewRecorder()

	h.AddComentario(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)
}

func TestIncidenciaHandler_IniciarInvestigacion_TransicionInvalida(t *testing.T) {
	t.Parallel()
	h := handlers.NewIncidenciaHandler(&fakeIncidenciaService{investigarErr: domain.ErrTransicionInvalida})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/incidencias/1/investigar", nil)
	req = withMuxVar(req, "id", "1")
	rec := httptest.NewRecorder()

	h.IniciarInvestigacion(rec, req)

	assert.Equal(t, http.StatusConflict, rec.Code)
}

func TestIncidenciaHandler_Cerrar_OK(t *testing.T) {
	t.Parallel()
	h := handlers.NewIncidenciaHandler(&fakeIncidenciaService{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/incidencias/1/cerrar", nil)
	req = withMuxVar(req, "id", "1")
	rec := httptest.NewRecorder()

	h.Cerrar(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}
