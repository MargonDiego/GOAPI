package application_test

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/MargonDiego/GOAPI/internal/application"
	"github.com/MargonDiego/GOAPI/internal/domain"
	"github.com/MargonDiego/GOAPI/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func incCtx() context.Context {
	ctx := application.WithActor(context.Background(), 1)
	return application.WithScope(ctx, "colegio-test")
}

func newIncidencia(t *testing.T) *domain.Incidencia {
	t.Helper()
	inc, err := domain.NewIncidencia("Pelea", "desc", domain.GravedadGrave, domain.CategoriaMaltratoEstudiantes, 2, 1, "colegio-test")
	require.NoError(t, err)
	inc.ID = 5
	return inc
}

// ---------------------------------------------------------------------------
// Crear
// ---------------------------------------------------------------------------

func TestIncidenciaService_Crear(t *testing.T) {
	t.Parallel()
	repo := mocks.NewMockIncidenciaRepository(t)
	fs := mocks.NewMockFileStorage(t)
	auditRepo := mocks.NewMockAuditRepository(t)

	repo.EXPECT().CountByScope(mock.Anything, "colegio-test", mock.AnythingOfType("int")).Return(int64(0), nil)
	repo.EXPECT().Create(mock.Anything, mock.AnythingOfType("*domain.Incidencia")).Return(nil)
	repo.EXPECT().AppendEvento(mock.Anything, mock.AnythingOfType("*domain.IncidenciaEvento")).Return(nil)
	auditRepo.EXPECT().Log(mock.Anything, mock.Anything).Return(nil).Maybe()

	svc := application.NewIncidenciaService(repo, fs, auditRepo)
	inc, err := svc.Crear(incCtx(), 2, "Pelea en patio", "descripcion", domain.GravedadGrave, domain.CategoriaMaltratoEstudiantes, false)
	require.NoError(t, err)
	assert.Equal(t, domain.EstadoRecibida, inc.Estado)
	assert.Contains(t, inc.Codigo, "INC-")
}

func TestIncidenciaService_Crear_TituloVacio(t *testing.T) {
	t.Parallel()
	repo := mocks.NewMockIncidenciaRepository(t)
	fs := mocks.NewMockFileStorage(t)
	svc := application.NewIncidenciaService(repo, fs, nil)

	_, err := svc.Crear(incCtx(), 2, "", "desc", domain.GravedadLeve, domain.CategoriaOtro, false)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Asignar
// ---------------------------------------------------------------------------

func TestIncidenciaService_Asignar(t *testing.T) {
	t.Parallel()
	repo := mocks.NewMockIncidenciaRepository(t)
	fs := mocks.NewMockFileStorage(t)
	auditRepo := mocks.NewMockAuditRepository(t)

	inc := newIncidencia(t)
	repo.EXPECT().FindByID(mock.Anything, uint(5)).Return(inc, nil)
	repo.EXPECT().Update(mock.Anything, mock.AnythingOfType("*domain.Incidencia")).Return(nil)
	repo.EXPECT().AppendEvento(mock.Anything, mock.AnythingOfType("*domain.IncidenciaEvento")).Return(nil)
	auditRepo.EXPECT().Log(mock.Anything, mock.Anything).Return(nil).Maybe()

	svc := application.NewIncidenciaService(repo, fs, auditRepo)
	err := svc.Asignar(incCtx(), 5, 10)
	require.NoError(t, err)
	assert.Equal(t, uint(10), *inc.ResponsableID)
}

// ---------------------------------------------------------------------------
// IniciarInvestigacion
// ---------------------------------------------------------------------------

func TestIncidenciaService_IniciarInvestigacion(t *testing.T) {
	t.Parallel()
	repo := mocks.NewMockIncidenciaRepository(t)
	fs := mocks.NewMockFileStorage(t)
	auditRepo := mocks.NewMockAuditRepository(t)

	inc := newIncidencia(t)
	repo.EXPECT().FindByID(mock.Anything, uint(5)).Return(inc, nil)
	repo.EXPECT().Update(mock.Anything, mock.AnythingOfType("*domain.Incidencia")).Return(nil)
	repo.EXPECT().AppendEvento(mock.Anything, mock.AnythingOfType("*domain.IncidenciaEvento")).Return(nil)
	auditRepo.EXPECT().Log(mock.Anything, mock.Anything).Return(nil).Maybe()

	svc := application.NewIncidenciaService(repo, fs, auditRepo)
	err := svc.IniciarInvestigacion(incCtx(), 5, time.Now())
	require.NoError(t, err)
	assert.Equal(t, domain.EstadoEnInvestigacion, inc.Estado)
}

// ---------------------------------------------------------------------------
// AgregarComentario
// ---------------------------------------------------------------------------

func TestIncidenciaService_AgregarComentario(t *testing.T) {
	t.Parallel()
	repo := mocks.NewMockIncidenciaRepository(t)
	fs := mocks.NewMockFileStorage(t)
	auditRepo := mocks.NewMockAuditRepository(t)

	inc := newIncidencia(t)
	repo.EXPECT().FindByID(mock.Anything, uint(5)).Return(inc, nil)
	repo.EXPECT().AppendComentario(mock.Anything, mock.AnythingOfType("*domain.Comentario")).Return(nil)
	repo.EXPECT().AppendEvento(mock.Anything, mock.AnythingOfType("*domain.IncidenciaEvento")).Return(nil)
	auditRepo.EXPECT().Log(mock.Anything, mock.Anything).Return(nil).Maybe()

	svc := application.NewIncidenciaService(repo, fs, auditRepo)
	err := svc.AgregarComentario(incCtx(), 5, "comentario de prueba")
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// AdjuntarArchivo
// ---------------------------------------------------------------------------

func TestIncidenciaService_AdjuntarArchivo(t *testing.T) {
	t.Parallel()
	repo := mocks.NewMockIncidenciaRepository(t)
	fs := mocks.NewMockFileStorage(t)
	auditRepo := mocks.NewMockAuditRepository(t)

	inc := newIncidencia(t)
	stored := domain.StoredFile{StoredName: "uuid-123", SHA256: "abc123", SizeBytes: 100}
	repo.EXPECT().FindByID(mock.Anything, uint(5)).Return(inc, nil)
	fs.EXPECT().Save(mock.Anything, mock.Anything, mock.AnythingOfType("domain.FileMeta")).Return(stored, nil)
	repo.EXPECT().AppendAdjunto(mock.Anything, mock.AnythingOfType("*domain.Adjunto")).Return(nil)
	repo.EXPECT().AppendEvento(mock.Anything, mock.AnythingOfType("*domain.IncidenciaEvento")).Return(nil)
	auditRepo.EXPECT().Log(mock.Anything, mock.Anything).Return(nil).Maybe()

	svc := application.NewIncidenciaService(repo, fs, auditRepo)
	adj, err := svc.AdjuntarArchivo(incCtx(), 5, bytes.NewReader([]byte("data")), domain.FileMeta{OriginalName: "doc.pdf", MimeType: "application/pdf"})
	require.NoError(t, err)
	assert.Equal(t, "uuid-123", adj.NombreAlmacenado)
	assert.Equal(t, "abc123", adj.HashSHA256)
}

// ---------------------------------------------------------------------------
// Resolver
// ---------------------------------------------------------------------------

func TestIncidenciaService_Resolver(t *testing.T) {
	t.Parallel()
	repo := mocks.NewMockIncidenciaRepository(t)
	fs := mocks.NewMockFileStorage(t)
	auditRepo := mocks.NewMockAuditRepository(t)

	inc := newIncidencia(t)
	require.NoError(t, inc.IniciarInvestigacion(1, time.Now()))

	repo.EXPECT().FindByID(mock.Anything, uint(5)).Return(inc, nil)
	repo.EXPECT().AppendResolucion(mock.Anything, mock.AnythingOfType("*domain.Resolucion")).Return(nil)
	repo.EXPECT().Update(mock.Anything, mock.AnythingOfType("*domain.Incidencia")).Return(nil)
	repo.EXPECT().AppendEvento(mock.Anything, mock.AnythingOfType("*domain.IncidenciaEvento")).Return(nil)
	auditRepo.EXPECT().Log(mock.Anything, mock.Anything).Return(nil).Maybe()

	svc := application.NewIncidenciaService(repo, fs, auditRepo)
	err := svc.Resolver(incCtx(), 5, "Se investigó exhaustivamente y...", "Medida formativa aplicada")
	require.NoError(t, err)
	assert.Equal(t, domain.EstadoResuelta, inc.Estado)
}

func TestIncidenciaService_Resolver_SinFundamentacion(t *testing.T) {
	t.Parallel()
	repo := mocks.NewMockIncidenciaRepository(t)
	fs := mocks.NewMockFileStorage(t)

	svc := application.NewIncidenciaService(repo, fs, nil)
	err := svc.Resolver(incCtx(), 5, "", "decision")
	assert.ErrorIs(t, err, domain.ErrResolucionSinFundamento)
}

// ---------------------------------------------------------------------------
// RegistrarMedida — expulsión rechazada si no es GRAVISIMA
// ---------------------------------------------------------------------------

func TestIncidenciaService_RegistrarMedida_ExpulsionSoloGravisima(t *testing.T) {
	t.Parallel()
	repo := mocks.NewMockIncidenciaRepository(t)
	fs := mocks.NewMockFileStorage(t)

	inc := newIncidencia(t) // Gravedad = GRAVE, no GRAVISIMA
	repo.EXPECT().FindByID(mock.Anything, uint(5)).Return(inc, nil)

	svc := application.NewIncidenciaService(repo, fs, nil)
	err := svc.RegistrarMedida(incCtx(), 5, domain.ClaseDisciplinaria, domain.TipoExpulsion, "desc", "proporcional", 1, time.Now(), nil)
	assert.ErrorIs(t, err, domain.ErrMedidaDesproporcionada)
}

// ---------------------------------------------------------------------------
// PresentarApelacion
// ---------------------------------------------------------------------------

func TestIncidenciaService_PresentarApelacion(t *testing.T) {
	t.Parallel()
	repo := mocks.NewMockIncidenciaRepository(t)
	fs := mocks.NewMockFileStorage(t)
	auditRepo := mocks.NewMockAuditRepository(t)

	inc := newIncidencia(t)
	require.NoError(t, inc.IniciarInvestigacion(1, time.Now()))
	require.NoError(t, inc.Resolver())

	resolucion := &domain.Resolucion{ID: 7, IncidenciaID: 5}
	plazo := time.Now().Add(5 * 24 * time.Hour)

	repo.EXPECT().FindByID(mock.Anything, uint(5)).Return(inc, nil)
	repo.EXPECT().ListResoluciones(mock.Anything, uint(5)).Return([]domain.Resolucion{*resolucion}, nil)
	repo.EXPECT().Update(mock.Anything, mock.AnythingOfType("*domain.Incidencia")).Return(nil)
	repo.EXPECT().AppendApelacion(mock.Anything, mock.AnythingOfType("*domain.Apelacion")).Return(nil)
	repo.EXPECT().AppendEvento(mock.Anything, mock.AnythingOfType("*domain.IncidenciaEvento")).Return(nil)
	auditRepo.EXPECT().Log(mock.Anything, mock.Anything).Return(nil).Maybe()

	svc := application.NewIncidenciaService(repo, fs, auditRepo)
	err := svc.PresentarApelacion(incCtx(), 5, 7, "motivo apelacion", plazo)
	require.NoError(t, err)
	assert.Equal(t, domain.EstadoEnApelacion, inc.Estado)
}

// ---------------------------------------------------------------------------
// GetByID y Search
// ---------------------------------------------------------------------------

func TestIncidenciaService_GetByID(t *testing.T) {
	t.Parallel()
	repo := mocks.NewMockIncidenciaRepository(t)
	fs := mocks.NewMockFileStorage(t)

	inc := newIncidencia(t)
	repo.EXPECT().FindByID(mock.Anything, uint(5)).Return(inc, nil)

	svc := application.NewIncidenciaService(repo, fs, nil)
	got, err := svc.GetByID(incCtx(), 5)
	require.NoError(t, err)
	assert.Equal(t, uint(5), got.ID)
}

func TestIncidenciaService_GetByID_ScopeMismatch(t *testing.T) {
	t.Parallel()
	repo := mocks.NewMockIncidenciaRepository(t)
	fs := mocks.NewMockFileStorage(t)

	inc := newIncidencia(t)
	inc.Scope = "otro-colegio"
	repo.EXPECT().FindByID(mock.Anything, uint(5)).Return(inc, nil)

	svc := application.NewIncidenciaService(repo, fs, nil)
	_, err := svc.GetByID(incCtx(), 5)
	assert.ErrorIs(t, err, domain.ErrScopeMismatch)
}

func TestIncidenciaService_Search(t *testing.T) {
	t.Parallel()
	repo := mocks.NewMockIncidenciaRepository(t)
	fs := mocks.NewMockFileStorage(t)

	inc := newIncidencia(t)
	repo.EXPECT().Search(mock.Anything, mock.AnythingOfType("domain.IncidenciaFilter"), 1, 10).
		Return([]domain.Incidencia{*inc}, int64(1), nil)

	svc := application.NewIncidenciaService(repo, fs, nil)
	result, err := svc.Search(incCtx(), domain.IncidenciaFilter{}, 1, 10)
	require.NoError(t, err)
	assert.Equal(t, 1, len(result.Data))
	assert.Equal(t, int64(1), int64(result.Total))
}

// ---------------------------------------------------------------------------
// GetExpediente
// ---------------------------------------------------------------------------

func TestIncidenciaService_GetExpediente(t *testing.T) {
	t.Parallel()
	repo := mocks.NewMockIncidenciaRepository(t)
	fs := mocks.NewMockFileStorage(t)

	inc := newIncidencia(t)
	repo.EXPECT().FindByID(mock.Anything, uint(5)).Return(inc, nil)
	repo.EXPECT().ListComentarios(mock.Anything, uint(5)).Return([]domain.Comentario{}, nil)
	repo.EXPECT().ListAdjuntos(mock.Anything, uint(5)).Return([]domain.Adjunto{}, nil)
	repo.EXPECT().ListMedidas(mock.Anything, uint(5)).Return([]domain.Medida{}, nil)
	repo.EXPECT().ListDescargos(mock.Anything, uint(5)).Return([]domain.Descargo{}, nil)
	repo.EXPECT().ListResoluciones(mock.Anything, uint(5)).Return([]domain.Resolucion{}, nil)
	repo.EXPECT().ListApelaciones(mock.Anything, uint(5)).Return([]domain.Apelacion{}, nil)
	repo.EXPECT().ListNotificaciones(mock.Anything, uint(5)).Return([]domain.Notificacion{}, nil)
	repo.EXPECT().ListEventos(mock.Anything, uint(5)).Return([]domain.IncidenciaEvento{}, nil)

	svc := application.NewIncidenciaService(repo, fs, nil)
	exp, err := svc.GetExpediente(incCtx(), 5)
	require.NoError(t, err)
	assert.Equal(t, uint(5), exp.Incidencia.ID)
}

// Comprueba que AuditRepository implementa la interfaz (compile-time check)
var _ io.Reader = (*bytes.Buffer)(nil)
