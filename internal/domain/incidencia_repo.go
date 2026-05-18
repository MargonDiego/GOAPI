package domain

import "context"

// IncidenciaReader agrupa las operaciones de consulta del agregado.
type IncidenciaReader interface {
	FindByID(ctx context.Context, id uint) (*Incidencia, error)
	FindByCodigo(ctx context.Context, codigo string) (*Incidencia, error)
	Search(ctx context.Context, f IncidenciaFilter, page, size int) ([]Incidencia, int64, error)
	FindAdjunto(ctx context.Context, adjID uint) (*Adjunto, error)
	FindApelacion(ctx context.Context, apelacionID uint) (*Apelacion, error)
	ListComentarios(ctx context.Context, incID uint) ([]Comentario, error)
	ListAdjuntos(ctx context.Context, incID uint) ([]Adjunto, error)
	ListMedidas(ctx context.Context, incID uint) ([]Medida, error)
	ListDescargos(ctx context.Context, incID uint) ([]Descargo, error)
	ListResoluciones(ctx context.Context, incID uint) ([]Resolucion, error)
	ListApelaciones(ctx context.Context, incID uint) ([]Apelacion, error)
	ListNotificaciones(ctx context.Context, incID uint) ([]Notificacion, error)
	ListEventos(ctx context.Context, incID uint) ([]IncidenciaEvento, error)
	CountByScope(ctx context.Context, scope string, year int) (int64, error)
}

// IncidenciaWriter agrupa las operaciones de mutación del agregado.
type IncidenciaWriter interface {
	Create(ctx context.Context, inc *Incidencia) error
	Update(ctx context.Context, inc *Incidencia) error
	AppendComentario(ctx context.Context, c *Comentario) error
	AppendAdjunto(ctx context.Context, a *Adjunto) error
	AppendMedida(ctx context.Context, m *Medida) error
	AppendDescargo(ctx context.Context, d *Descargo) error
	AppendResolucion(ctx context.Context, r *Resolucion) error
	AppendApelacion(ctx context.Context, a *Apelacion) error
	AppendNotificacion(ctx context.Context, n *Notificacion) error
	AppendEvento(ctx context.Context, e *IncidenciaEvento) error
	UpdateApelacionEstado(ctx context.Context, apelacionID uint, estado EstadoApelacion) error
	UpdateAcuseNotificacion(ctx context.Context, notifID uint, fecha interface{}) error
}

// IncidenciaRepository es el puerto de persistencia completo del agregado.
type IncidenciaRepository interface {
	IncidenciaReader
	IncidenciaWriter
}
