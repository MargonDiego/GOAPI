package persistence

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/MargonDiego/GOAPI/internal/domain"
	"gorm.io/gorm"
)

type incidenciaRepository struct {
	db *gorm.DB
}

func NewIncidenciaRepository(db *gorm.DB) domain.IncidenciaRepository {
	return &incidenciaRepository{db: db}
}

func (r *incidenciaRepository) ctx(ctx context.Context) *gorm.DB {
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	_ = cancel
	return r.db.WithContext(cctx)
}

// ---------------------------------------------------------------------------
// IncidenciaReader
// ---------------------------------------------------------------------------

func (r *incidenciaRepository) FindByID(ctx context.Context, id uint) (*domain.Incidencia, error) {
	var m IncidenciaDB
	if err := r.ctx(ctx).First(&m, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrIncidenciaNotFound
		}
		return nil, fmt.Errorf("find incidencia: %w", err)
	}
	return toDomainIncidencia(&m), nil
}

func (r *incidenciaRepository) FindByCodigo(ctx context.Context, codigo string) (*domain.Incidencia, error) {
	var m IncidenciaDB
	if err := r.ctx(ctx).Where("codigo = ? AND deleted_at IS NULL", codigo).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrIncidenciaNotFound
		}
		return nil, fmt.Errorf("find incidencia by codigo: %w", err)
	}
	return toDomainIncidencia(&m), nil
}

func (r *incidenciaRepository) Search(ctx context.Context, f domain.IncidenciaFilter, page, size int) ([]domain.Incidencia, int64, error) {
	q := r.ctx(ctx).Model(&IncidenciaDB{})
	if f.Scope != "" {
		q = q.Where("scope = ?", f.Scope)
	}
	if f.Estado != "" {
		q = q.Where("estado = ?", string(f.Estado))
	}
	if f.Gravedad != "" {
		q = q.Where("gravedad = ?", string(f.Gravedad))
	}
	if f.Categoria != "" {
		q = q.Where("categoria = ?", string(f.Categoria))
	}
	if f.ResponsableID != nil {
		q = q.Where("responsable_id = ?", *f.ResponsableID)
	}
	if f.EstudianteID != nil {
		q = q.Where("estudiante_id = ?", *f.EstudianteID)
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("count incidencias: %w", err)
	}

	var rows []IncidenciaDB
	offset := (page - 1) * size
	if err := q.Order("created_at DESC").Limit(size).Offset(offset).Find(&rows).Error; err != nil {
		return nil, 0, fmt.Errorf("search incidencias: %w", err)
	}

	result := make([]domain.Incidencia, 0, len(rows))
	for i := range rows {
		result = append(result, *toDomainIncidencia(&rows[i]))
	}
	return result, total, nil
}

func (r *incidenciaRepository) FindAdjunto(ctx context.Context, adjID uint) (*domain.Adjunto, error) {
	var m AdjuntoDB
	if err := r.ctx(ctx).First(&m, adjID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrAdjuntoNotFound
		}
		return nil, fmt.Errorf("find adjunto: %w", err)
	}
	d := toDomainAdjunto(m)
	return &d, nil
}

func (r *incidenciaRepository) FindApelacion(ctx context.Context, apelacionID uint) (*domain.Apelacion, error) {
	var m ApelacionDB
	if err := r.ctx(ctx).First(&m, apelacionID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrApelacionNotFound
		}
		return nil, fmt.Errorf("find apelacion: %w", err)
	}
	d := toDomainApelacion(m)
	return &d, nil
}

func (r *incidenciaRepository) ListComentarios(ctx context.Context, incID uint) ([]domain.Comentario, error) {
	var rows []ComentarioDB
	if err := r.ctx(ctx).Where("incidencia_id = ?", incID).Order("created_at ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list comentarios: %w", err)
	}
	result := make([]domain.Comentario, 0, len(rows))
	for _, m := range rows {
		result = append(result, toDomainComentario(m))
	}
	return result, nil
}

func (r *incidenciaRepository) ListAdjuntos(ctx context.Context, incID uint) ([]domain.Adjunto, error) {
	var rows []AdjuntoDB
	if err := r.ctx(ctx).Where("incidencia_id = ?", incID).Order("created_at ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list adjuntos: %w", err)
	}
	result := make([]domain.Adjunto, 0, len(rows))
	for _, m := range rows {
		result = append(result, toDomainAdjunto(m))
	}
	return result, nil
}

func (r *incidenciaRepository) ListMedidas(ctx context.Context, incID uint) ([]domain.Medida, error) {
	var rows []MedidaDB
	if err := r.ctx(ctx).Where("incidencia_id = ?", incID).Order("created_at ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list medidas: %w", err)
	}
	result := make([]domain.Medida, 0, len(rows))
	for _, m := range rows {
		result = append(result, toDomainMedida(m))
	}
	return result, nil
}

func (r *incidenciaRepository) ListDescargos(ctx context.Context, incID uint) ([]domain.Descargo, error) {
	var rows []DescargoDB
	if err := r.ctx(ctx).Where("incidencia_id = ?", incID).Order("created_at ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list descargos: %w", err)
	}
	result := make([]domain.Descargo, 0, len(rows))
	for _, m := range rows {
		result = append(result, toDomainDescargo(m))
	}
	return result, nil
}

func (r *incidenciaRepository) ListResoluciones(ctx context.Context, incID uint) ([]domain.Resolucion, error) {
	var rows []ResolucionDB
	if err := r.ctx(ctx).Where("incidencia_id = ?", incID).Order("created_at ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list resoluciones: %w", err)
	}
	result := make([]domain.Resolucion, 0, len(rows))
	for _, m := range rows {
		result = append(result, toDomainResolucion(m))
	}
	return result, nil
}

func (r *incidenciaRepository) ListApelaciones(ctx context.Context, incID uint) ([]domain.Apelacion, error) {
	var rows []ApelacionDB
	if err := r.ctx(ctx).Where("incidencia_id = ?", incID).Order("created_at ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list apelaciones: %w", err)
	}
	result := make([]domain.Apelacion, 0, len(rows))
	for _, m := range rows {
		result = append(result, toDomainApelacion(m))
	}
	return result, nil
}

func (r *incidenciaRepository) ListNotificaciones(ctx context.Context, incID uint) ([]domain.Notificacion, error) {
	var rows []NotificacionDB
	if err := r.ctx(ctx).Where("incidencia_id = ?", incID).Order("created_at ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list notificaciones: %w", err)
	}
	result := make([]domain.Notificacion, 0, len(rows))
	for _, m := range rows {
		result = append(result, toDomainNotificacion(m))
	}
	return result, nil
}

func (r *incidenciaRepository) ListEventos(ctx context.Context, incID uint) ([]domain.IncidenciaEvento, error) {
	var rows []IncidenciaEventoDB
	if err := r.ctx(ctx).Where("incidencia_id = ?", incID).Order("created_at ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list eventos: %w", err)
	}
	result := make([]domain.IncidenciaEvento, 0, len(rows))
	for _, m := range rows {
		result = append(result, toDomainEvento(m))
	}
	return result, nil
}

func (r *incidenciaRepository) CountByScope(ctx context.Context, scope string, year int) (int64, error) {
	var count int64
	err := r.ctx(ctx).Model(&IncidenciaDB{}).
		Where("scope = ? AND EXTRACT(YEAR FROM fecha_recepcion) = ?", scope, year).
		Count(&count).Error
	if err != nil {
		return 0, fmt.Errorf("count by scope: %w", err)
	}
	return count, nil
}

// ---------------------------------------------------------------------------
// IncidenciaWriter
// ---------------------------------------------------------------------------

func (r *incidenciaRepository) Create(ctx context.Context, inc *domain.Incidencia) error {
	m := toDBIncidencia(inc)
	if err := r.ctx(ctx).Create(m).Error; err != nil {
		return fmt.Errorf("create incidencia: %w", err)
	}
	inc.ID = m.ID
	return nil
}

func (r *incidenciaRepository) Update(ctx context.Context, inc *domain.Incidencia) error {
	m := toDBIncidencia(inc)
	if err := r.ctx(ctx).Save(m).Error; err != nil {
		return fmt.Errorf("update incidencia: %w", err)
	}
	return nil
}

func (r *incidenciaRepository) AppendComentario(ctx context.Context, c *domain.Comentario) error {
	m := &ComentarioDB{IncidenciaID: c.IncidenciaID, AutorID: c.AutorID, Cuerpo: c.Cuerpo}
	if err := r.ctx(ctx).Create(m).Error; err != nil {
		return fmt.Errorf("append comentario: %w", err)
	}
	c.ID = m.ID
	return nil
}

func (r *incidenciaRepository) AppendAdjunto(ctx context.Context, a *domain.Adjunto) error {
	m := &AdjuntoDB{IncidenciaID: a.IncidenciaID, NombreOriginal: a.NombreOriginal, NombreAlmacenado: a.NombreAlmacenado, MimeType: a.MimeType, TamanoBytes: a.TamanoBytes, HashSHA256: a.HashSHA256, SubidoPorID: a.SubidoPorID}
	if err := r.ctx(ctx).Create(m).Error; err != nil {
		return fmt.Errorf("append adjunto: %w", err)
	}
	a.ID = m.ID
	return nil
}

func (r *incidenciaRepository) AppendMedida(ctx context.Context, med *domain.Medida) error {
	m := &MedidaDB{IncidenciaID: med.IncidenciaID, Clase: string(med.Clase), Tipo: string(med.Tipo), Descripcion: med.Descripcion, Proporcionalidad: med.Proporcionalidad, ResponsableEjecucionID: med.ResponsableEjecucionID, FechaInicio: med.FechaInicio, FechaTermino: med.FechaTermino, EstadoCumplimiento: string(med.EstadoCumplimiento)}
	if err := r.ctx(ctx).Create(m).Error; err != nil {
		return fmt.Errorf("append medida: %w", err)
	}
	med.ID = m.ID
	return nil
}

func (r *incidenciaRepository) AppendDescargo(ctx context.Context, d *domain.Descargo) error {
	m := &DescargoDB{IncidenciaID: d.IncidenciaID, PresentadoPorID: d.PresentadoPorID, Contenido: d.Contenido, FechaPresentacion: d.FechaPresentacion}
	if err := r.ctx(ctx).Create(m).Error; err != nil {
		return fmt.Errorf("append descargo: %w", err)
	}
	d.ID = m.ID
	return nil
}

func (r *incidenciaRepository) AppendResolucion(ctx context.Context, res *domain.Resolucion) error {
	m := &ResolucionDB{IncidenciaID: res.IncidenciaID, Tipo: string(res.Tipo), Fundamentacion: res.Fundamentacion, Decision: res.Decision, ResueltoPorID: res.ResueltoPorID, FechaResolucion: res.FechaResolucion}
	if err := r.ctx(ctx).Create(m).Error; err != nil {
		return fmt.Errorf("append resolucion: %w", err)
	}
	res.ID = m.ID
	return nil
}

func (r *incidenciaRepository) AppendApelacion(ctx context.Context, a *domain.Apelacion) error {
	m := &ApelacionDB{IncidenciaID: a.IncidenciaID, ResolucionID: a.ResolucionID, PresentadaPorID: a.PresentadaPorID, Motivo: a.Motivo, FechaPresentacion: a.FechaPresentacion, PlazoVencimiento: a.PlazoVencimiento, Estado: string(a.Estado)}
	if err := r.ctx(ctx).Create(m).Error; err != nil {
		return fmt.Errorf("append apelacion: %w", err)
	}
	a.ID = m.ID
	return nil
}

func (r *incidenciaRepository) AppendNotificacion(ctx context.Context, n *domain.Notificacion) error {
	m := &NotificacionDB{IncidenciaID: n.IncidenciaID, Destinatario: n.Destinatario, Medio: n.Medio, Contenido: n.Contenido, FechaNotificacion: n.FechaNotificacion, Acuse: n.Acuse, FechaAcuse: n.FechaAcuse}
	if err := r.ctx(ctx).Create(m).Error; err != nil {
		return fmt.Errorf("append notificacion: %w", err)
	}
	n.ID = m.ID
	return nil
}

func (r *incidenciaRepository) AppendEvento(ctx context.Context, e *domain.IncidenciaEvento) error {
	m := &IncidenciaEventoDB{IncidenciaID: e.IncidenciaID, Tipo: string(e.Tipo), ActorID: e.ActorID, Resumen: e.Resumen, EstadoAnterior: e.EstadoAnterior, EstadoNuevo: e.EstadoNuevo}
	if err := r.ctx(ctx).Create(m).Error; err != nil {
		return fmt.Errorf("append evento: %w", err)
	}
	e.ID = m.ID
	return nil
}

func (r *incidenciaRepository) UpdateApelacionEstado(ctx context.Context, apelacionID uint, estado domain.EstadoApelacion) error {
	result := r.ctx(ctx).Model(&ApelacionDB{}).Where("id = ?", apelacionID).Update("estado", string(estado))
	if result.Error != nil {
		return fmt.Errorf("update apelacion estado: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return domain.ErrApelacionNotFound
	}
	return nil
}

func (r *incidenciaRepository) UpdateAcuseNotificacion(ctx context.Context, notifID uint, fecha interface{}) error {
	result := r.ctx(ctx).Model(&NotificacionDB{}).Where("id = ?", notifID).Updates(map[string]interface{}{"acuse": true, "fecha_acuse": fecha})
	if result.Error != nil {
		return fmt.Errorf("update acuse notificacion: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("notificacion %d not found", notifID)
	}
	return nil
}
