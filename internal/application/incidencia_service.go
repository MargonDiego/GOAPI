package application

import (
	"context"
	"io"
	"time"

	"github.com/MargonDiego/GOAPI/internal/domain"
)

// Expediente agrupa el estado completo de una incidencia con su historial.
type Expediente struct {
	Incidencia     *domain.Incidencia
	Comentarios    []domain.Comentario
	Adjuntos       []domain.Adjunto
	Medidas        []domain.Medida
	Descargos      []domain.Descargo
	Resoluciones   []domain.Resolucion
	Apelaciones    []domain.Apelacion
	Notificaciones []domain.Notificacion
	Eventos        []domain.IncidenciaEvento
}

// IncidenciaService orquesta el ciclo de vida del expediente de convivencia.
type IncidenciaService interface {
	Crear(ctx context.Context, estudianteID uint, titulo, descripcion string, gravedad domain.GravedadIncidencia, categoria domain.CategoriaIncidencia, esDelito bool) (*domain.Incidencia, error)
	Asignar(ctx context.Context, id, responsableID uint) error
	IniciarInvestigacion(ctx context.Context, id uint, fecha time.Time) error
	AgregarComentario(ctx context.Context, id uint, cuerpo string) error
	AdjuntarArchivo(ctx context.Context, id uint, r io.Reader, meta domain.FileMeta) (*domain.Adjunto, error)
	RegistrarDescargo(ctx context.Context, id uint, contenido string) error
	RegistrarMedida(ctx context.Context, id uint, clase domain.ClaseMedida, tipo domain.TipoMedida, descripcion, proporcionalidad string, responsableEjecID uint, fechaInicio time.Time, fechaTermino *time.Time) error
	Resolver(ctx context.Context, id uint, fundamentacion, decision string) error
	RegistrarNotificacion(ctx context.Context, id uint, destinatario, medio, contenido string, fecha time.Time) error
	PresentarApelacion(ctx context.Context, id, resolucionID uint, motivo string, plazoVencimiento time.Time) error
	ResolverApelacion(ctx context.Context, apelacionID uint, fundamentacion, decision string, aceptada bool) error
	Derivar(ctx context.Context, id uint) error
	IniciarSeguimiento(ctx context.Context, id uint) error
	Cerrar(ctx context.Context, id uint) error
	ObtenerAdjunto(ctx context.Context, adjID uint) (*domain.Adjunto, io.ReadCloser, error)
	GetByID(ctx context.Context, id uint) (*domain.Incidencia, error)
	Search(ctx context.Context, f domain.IncidenciaFilter, page, size int) (domain.PaginatedResult[domain.Incidencia], error)
	GetExpediente(ctx context.Context, id uint) (*Expediente, error)
	ConfirmarAcuseNotificacion(ctx context.Context, notifID uint) error
}
