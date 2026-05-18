package application

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/MargonDiego/GOAPI/internal/domain"
	appcrypto "github.com/MargonDiego/GOAPI/internal/infrastructure/crypto"
)

type incidenciaService struct {
	repo  domain.IncidenciaRepository
	fs    domain.FileStorage
	audit auditService
}

// NewIncidenciaService construye el servicio. auditRepo puede ser nil.
func NewIncidenciaService(repo domain.IncidenciaRepository, fs domain.FileStorage, auditRepo domain.AuditRepository) IncidenciaService {
	return &incidenciaService{repo: repo, fs: fs, audit: newAuditService(auditRepo)}
}

// NewIncidenciaServiceWithEnc construye el servicio con encryptor (futuro: cifrado narrativa).
// Incluido para satisfacer el wiring en main.go sin romper la interfaz pública.
func NewIncidenciaServiceWithEnc(repo domain.IncidenciaRepository, fs domain.FileStorage, _ *appcrypto.Encryptor, auditRepo domain.AuditRepository) IncidenciaService {
	return NewIncidenciaService(repo, fs, auditRepo)
}

func (s *incidenciaService) generateCodigo(ctx context.Context, scope string) (string, error) {
	year := time.Now().Year()
	count, err := s.repo.CountByScope(ctx, scope, year)
	if err != nil {
		return "", fmt.Errorf("count incidencias: %w", err)
	}
	return fmt.Sprintf("INC-%d-%04d", year, count+1), nil
}

func (s *incidenciaService) Crear(ctx context.Context, estudianteID uint, titulo, descripcion string, gravedad domain.GravedadIncidencia, categoria domain.CategoriaIncidencia, esDelito bool) (*domain.Incidencia, error) {
	scope, _ := ScopeFromContext(ctx)
	actorID, _ := ActorFromContext(ctx)

	// Validar invariantes ANTES de ir a la BD.
	inc, err := domain.NewIncidencia(titulo, descripcion, gravedad, categoria, estudianteID, actorID, scope)
	if err != nil {
		return nil, err
	}

	codigo, err := s.generateCodigo(ctx, scope)
	if err != nil {
		return nil, err
	}
	inc.Codigo = codigo
	inc.EsConstitutivoDeDelito = esDelito

	if err := s.repo.Create(ctx, inc); err != nil {
		return nil, fmt.Errorf("create incidencia: %w", err)
	}

	evento := domain.NewIncidenciaEvento(inc.ID, domain.EventoCreacion, actorID, "Incidencia creada", nil, nil)
	_ = s.repo.AppendEvento(ctx, evento)

	s.audit.log(ctx, "create_incidencia", "incidencia", inc.ID, nil, map[string]any{"codigo": codigo, "gravedad": string(gravedad)})
	return inc, nil
}

func (s *incidenciaService) Asignar(ctx context.Context, id, responsableID uint) error {
	actorID, _ := ActorFromContext(ctx)

	inc, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("%w", err)
	}
	if err := assertScopeAccess(ctx, inc.Scope); err != nil {
		return err
	}

	inc.ResponsableID = &responsableID
	if err := s.repo.Update(ctx, inc); err != nil {
		return fmt.Errorf("update incidencia: %w", err)
	}

	evento := domain.NewIncidenciaEvento(id, domain.EventoAsignacion, actorID, fmt.Sprintf("Asignado responsable ID=%d", responsableID), nil, nil)
	_ = s.repo.AppendEvento(ctx, evento)
	s.audit.log(ctx, "asignar_incidencia", "incidencia", id, nil, map[string]any{"responsable_id": responsableID})
	return nil
}

func (s *incidenciaService) IniciarInvestigacion(ctx context.Context, id uint, fecha time.Time) error {
	actorID, _ := ActorFromContext(ctx)

	inc, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("%w", err)
	}
	if err := assertScopeAccess(ctx, inc.Scope); err != nil {
		return err
	}

	prev := inc.Estado
	if err := inc.IniciarInvestigacion(actorID, fecha); err != nil {
		return err
	}
	if err := s.repo.Update(ctx, inc); err != nil {
		return fmt.Errorf("update incidencia: %w", err)
	}

	nuevo := inc.Estado
	evento := domain.NewIncidenciaEvento(id, domain.EventoCambioEstado, actorID, "Investigacion iniciada", &prev, &nuevo)
	_ = s.repo.AppendEvento(ctx, evento)
	s.audit.log(ctx, "iniciar_investigacion", "incidencia", id, nil, nil)
	return nil
}

func (s *incidenciaService) AgregarComentario(ctx context.Context, id uint, cuerpo string) error {
	actorID, _ := ActorFromContext(ctx)

	inc, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("%w", err)
	}
	if err := assertScopeAccess(ctx, inc.Scope); err != nil {
		return err
	}

	c, err := domain.NewComentario(id, actorID, cuerpo)
	if err != nil {
		return err
	}
	if err := s.repo.AppendComentario(ctx, c); err != nil {
		return fmt.Errorf("append comentario: %w", err)
	}

	evento := domain.NewIncidenciaEvento(id, domain.EventoComentario, actorID, "Comentario agregado", nil, nil)
	_ = s.repo.AppendEvento(ctx, evento)
	s.audit.log(ctx, "agregar_comentario", "incidencia", id, nil, nil)
	return nil
}

func (s *incidenciaService) AdjuntarArchivo(ctx context.Context, id uint, r io.Reader, meta domain.FileMeta) (*domain.Adjunto, error) {
	actorID, _ := ActorFromContext(ctx)

	inc, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	if err := assertScopeAccess(ctx, inc.Scope); err != nil {
		return nil, err
	}

	stored, err := s.fs.Save(ctx, r, meta)
	if err != nil {
		return nil, fmt.Errorf("save file: %w", err)
	}

	adj := &domain.Adjunto{
		IncidenciaID:     id,
		NombreOriginal:   meta.OriginalName,
		NombreAlmacenado: stored.StoredName,
		MimeType:         meta.MimeType,
		TamanoBytes:      stored.SizeBytes,
		HashSHA256:       stored.SHA256,
		SubidoPorID:      actorID,
		CreatedAt:        time.Now(),
	}
	if err := s.repo.AppendAdjunto(ctx, adj); err != nil {
		_ = s.fs.Delete(ctx, stored.StoredName)
		return nil, fmt.Errorf("append adjunto: %w", err)
	}

	evento := domain.NewIncidenciaEvento(id, domain.EventoAdjunto, actorID, "Adjunto agregado: "+meta.OriginalName, nil, nil)
	_ = s.repo.AppendEvento(ctx, evento)
	s.audit.log(ctx, "adjuntar_archivo", "incidencia", id, nil, map[string]any{"nombre": meta.OriginalName})
	return adj, nil
}

func (s *incidenciaService) RegistrarDescargo(ctx context.Context, id uint, contenido string) error {
	actorID, _ := ActorFromContext(ctx)

	inc, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("%w", err)
	}
	if err := assertScopeAccess(ctx, inc.Scope); err != nil {
		return err
	}

	d, err := domain.NewDescargo(id, actorID, contenido)
	if err != nil {
		return err
	}
	if err := s.repo.AppendDescargo(ctx, d); err != nil {
		return fmt.Errorf("append descargo: %w", err)
	}

	evento := domain.NewIncidenciaEvento(id, domain.EventoDescargo, actorID, "Descargo registrado", nil, nil)
	_ = s.repo.AppendEvento(ctx, evento)
	s.audit.log(ctx, "registrar_descargo", "incidencia", id, nil, nil)
	return nil
}

func (s *incidenciaService) RegistrarMedida(ctx context.Context, id uint, clase domain.ClaseMedida, tipo domain.TipoMedida, descripcion, proporcionalidad string, responsableEjecID uint, fechaInicio time.Time, fechaTermino *time.Time) error {
	actorID, _ := ActorFromContext(ctx)

	inc, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("%w", err)
	}
	if err := assertScopeAccess(ctx, inc.Scope); err != nil {
		return err
	}

	// Invariante de proporcionalidad: expulsión/cancelación solo para faltas gravísimas.
	if (tipo == domain.TipoExpulsion || tipo == domain.TipoCancelacion) && inc.Gravedad != domain.GravedadGravisima {
		return domain.ErrMedidaDesproporcionada
	}

	m, err := domain.NewMedida(id, clase, tipo, descripcion, proporcionalidad, responsableEjecID, fechaInicio, fechaTermino)
	if err != nil {
		return err
	}
	if err := s.repo.AppendMedida(ctx, m); err != nil {
		return fmt.Errorf("append medida: %w", err)
	}

	evento := domain.NewIncidenciaEvento(id, domain.EventoMedida, actorID, "Medida registrada: "+string(tipo), nil, nil)
	_ = s.repo.AppendEvento(ctx, evento)
	s.audit.log(ctx, "registrar_medida", "incidencia", id, nil, map[string]any{"tipo": string(tipo)})
	return nil
}

func (s *incidenciaService) Resolver(ctx context.Context, id uint, fundamentacion, decision string) error {
	if strings.TrimSpace(fundamentacion) == "" {
		return domain.ErrResolucionSinFundamento
	}

	actorID, _ := ActorFromContext(ctx)

	inc, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("%w", err)
	}
	if err := assertScopeAccess(ctx, inc.Scope); err != nil {
		return err
	}

	r, err := domain.NewResolucion(id, domain.ResolucionOriginal, fundamentacion, decision, actorID)
	if err != nil {
		return err
	}
	if err := s.repo.AppendResolucion(ctx, r); err != nil {
		return fmt.Errorf("append resolucion: %w", err)
	}

	prev := inc.Estado
	if err := inc.Resolver(); err != nil {
		return err
	}
	if err := s.repo.Update(ctx, inc); err != nil {
		return fmt.Errorf("update incidencia: %w", err)
	}

	nuevo := inc.Estado
	evento := domain.NewIncidenciaEvento(id, domain.EventoResolucion, actorID, "Resolucion registrada", &prev, &nuevo)
	_ = s.repo.AppendEvento(ctx, evento)
	s.audit.log(ctx, "resolver_incidencia", "incidencia", id, nil, nil)
	return nil
}

func (s *incidenciaService) RegistrarNotificacion(ctx context.Context, id uint, destinatario, medio, contenido string, fecha time.Time) error {
	actorID, _ := ActorFromContext(ctx)

	inc, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("%w", err)
	}
	if err := assertScopeAccess(ctx, inc.Scope); err != nil {
		return err
	}

	n, err := domain.NewNotificacion(id, destinatario, medio, contenido, fecha)
	if err != nil {
		return err
	}
	if err := s.repo.AppendNotificacion(ctx, n); err != nil {
		return fmt.Errorf("append notificacion: %w", err)
	}

	evento := domain.NewIncidenciaEvento(id, domain.EventoNotificacion, actorID, "Notificacion a "+destinatario, nil, nil)
	_ = s.repo.AppendEvento(ctx, evento)
	s.audit.log(ctx, "registrar_notificacion", "incidencia", id, nil, map[string]any{"destinatario": destinatario})
	return nil
}

func (s *incidenciaService) PresentarApelacion(ctx context.Context, id, resolucionID uint, motivo string, plazoVencimiento time.Time) error {
	actorID, _ := ActorFromContext(ctx)

	inc, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("%w", err)
	}
	if err := assertScopeAccess(ctx, inc.Scope); err != nil {
		return err
	}

	// Verificar que la resolución pertenece a esta incidencia.
	resoluciones, err := s.repo.ListResoluciones(ctx, id)
	if err != nil {
		return fmt.Errorf("list resoluciones: %w", err)
	}
	found := false
	for _, r := range resoluciones {
		if r.ID == resolucionID {
			found = true
			break
		}
	}
	if !found {
		return domain.ErrIncidenciaNotFound
	}

	a, err := domain.NewApelacion(id, resolucionID, actorID, motivo, plazoVencimiento)
	if err != nil {
		return err
	}

	prev := inc.Estado
	if err := inc.IniciarApelacion(); err != nil {
		return err
	}
	if err := s.repo.Update(ctx, inc); err != nil {
		return fmt.Errorf("update incidencia: %w", err)
	}
	if err := s.repo.AppendApelacion(ctx, a); err != nil {
		return fmt.Errorf("append apelacion: %w", err)
	}

	nuevo := inc.Estado
	evento := domain.NewIncidenciaEvento(id, domain.EventoApelacion, actorID, "Apelacion presentada", &prev, &nuevo)
	_ = s.repo.AppendEvento(ctx, evento)
	s.audit.log(ctx, "presentar_apelacion", "incidencia", id, nil, nil)
	return nil
}

func (s *incidenciaService) ResolverApelacion(ctx context.Context, apelacionID uint, fundamentacion, decision string, aceptada bool) error {
	if strings.TrimSpace(fundamentacion) == "" {
		return domain.ErrResolucionSinFundamento
	}

	actorID, _ := ActorFromContext(ctx)

	apelacion, err := s.repo.FindApelacion(ctx, apelacionID)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	inc, err := s.repo.FindByID(ctx, apelacion.IncidenciaID)
	if err != nil {
		return fmt.Errorf("%w", err)
	}
	if err := assertScopeAccess(ctx, inc.Scope); err != nil {
		return err
	}

	r, err := domain.NewResolucion(inc.ID, domain.ResolucionApelacion, fundamentacion, decision, actorID)
	if err != nil {
		return err
	}
	if err := s.repo.AppendResolucion(ctx, r); err != nil {
		return fmt.Errorf("append resolucion apelacion: %w", err)
	}

	estado := domain.ApelacionRechazada
	if aceptada {
		estado = domain.ApelacionAceptada
	}
	if err := s.repo.UpdateApelacionEstado(ctx, apelacionID, estado); err != nil {
		return fmt.Errorf("update apelacion estado: %w", err)
	}

	prev := inc.Estado
	if err := inc.ResolverApelacion(); err != nil {
		return err
	}
	if err := s.repo.Update(ctx, inc); err != nil {
		return fmt.Errorf("update incidencia: %w", err)
	}

	nuevo := inc.Estado
	evento := domain.NewIncidenciaEvento(inc.ID, domain.EventoApelacion, actorID, "Apelacion resuelta", &prev, &nuevo)
	_ = s.repo.AppendEvento(ctx, evento)
	s.audit.log(ctx, "resolver_apelacion", "incidencia", inc.ID, nil, map[string]any{"aceptada": aceptada})
	return nil
}

func (s *incidenciaService) Derivar(ctx context.Context, id uint) error {
	actorID, _ := ActorFromContext(ctx)

	inc, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("%w", err)
	}
	if err := assertScopeAccess(ctx, inc.Scope); err != nil {
		return err
	}

	prev := inc.Estado
	if err := inc.Derivar(); err != nil {
		return err
	}
	if err := s.repo.Update(ctx, inc); err != nil {
		return fmt.Errorf("update incidencia: %w", err)
	}

	nuevo := inc.Estado
	evento := domain.NewIncidenciaEvento(id, domain.EventoCambioEstado, actorID, "Incidencia derivada", &prev, &nuevo)
	_ = s.repo.AppendEvento(ctx, evento)
	s.audit.log(ctx, "derivar_incidencia", "incidencia", id, nil, nil)
	return nil
}

func (s *incidenciaService) IniciarSeguimiento(ctx context.Context, id uint) error {
	actorID, _ := ActorFromContext(ctx)

	inc, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("%w", err)
	}
	if err := assertScopeAccess(ctx, inc.Scope); err != nil {
		return err
	}

	prev := inc.Estado
	if err := inc.IniciarSeguimiento(); err != nil {
		return err
	}
	if err := s.repo.Update(ctx, inc); err != nil {
		return fmt.Errorf("update incidencia: %w", err)
	}

	nuevo := inc.Estado
	evento := domain.NewIncidenciaEvento(id, domain.EventoCambioEstado, actorID, "Seguimiento iniciado", &prev, &nuevo)
	_ = s.repo.AppendEvento(ctx, evento)
	s.audit.log(ctx, "iniciar_seguimiento", "incidencia", id, nil, nil)
	return nil
}

func (s *incidenciaService) Cerrar(ctx context.Context, id uint) error {
	actorID, _ := ActorFromContext(ctx)

	inc, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("%w", err)
	}
	if err := assertScopeAccess(ctx, inc.Scope); err != nil {
		return err
	}

	// Verificar que no haya apelaciones PENDIENTE antes de cerrar.
	apelaciones, err := s.repo.ListApelaciones(ctx, id)
	if err != nil {
		return fmt.Errorf("list apelaciones: %w", err)
	}
	for _, a := range apelaciones {
		if a.Estado == domain.ApelacionPendiente {
			return domain.ErrTransicionInvalida
		}
	}

	prev := inc.Estado
	if err := inc.Cerrar(); err != nil {
		return err
	}
	if err := s.repo.Update(ctx, inc); err != nil {
		return fmt.Errorf("update incidencia: %w", err)
	}

	nuevo := inc.Estado
	evento := domain.NewIncidenciaEvento(id, domain.EventoCambioEstado, actorID, "Incidencia cerrada", &prev, &nuevo)
	_ = s.repo.AppendEvento(ctx, evento)
	s.audit.log(ctx, "cerrar_incidencia", "incidencia", id, nil, nil)
	return nil
}

func (s *incidenciaService) ObtenerAdjunto(ctx context.Context, adjID uint) (*domain.Adjunto, io.ReadCloser, error) {
	adj, err := s.repo.FindAdjunto(ctx, adjID)
	if err != nil {
		return nil, nil, fmt.Errorf("%w", err)
	}
	rc, err := s.fs.Open(ctx, adj.NombreAlmacenado)
	if err != nil {
		return nil, nil, fmt.Errorf("open file: %w", err)
	}
	s.audit.log(ctx, "descargar_adjunto", "adjunto", adjID, nil, nil)
	return adj, rc, nil
}

func (s *incidenciaService) GetByID(ctx context.Context, id uint) (*domain.Incidencia, error) {
	inc, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	if err := assertScopeAccess(ctx, inc.Scope); err != nil {
		return nil, err
	}
	s.audit.log(ctx, "read_incidencia", "incidencia", id, nil, nil)
	return inc, nil
}

func (s *incidenciaService) Search(ctx context.Context, f domain.IncidenciaFilter, page, size int) (domain.PaginatedResult[domain.Incidencia], error) {
	if page < 1 {
		page = 1
	}
	if size <= 0 || size > 100 {
		size = 10
	}
	scope, _ := ScopeFromContext(ctx)
	f.Scope = scope

	list, total, err := s.repo.Search(ctx, f, page, size)
	if err != nil {
		return domain.PaginatedResult[domain.Incidencia]{}, fmt.Errorf("search incidencias: %w", err)
	}
	return domain.NewPaginatedResult(list, page, size, int(total)), nil
}

func (s *incidenciaService) GetExpediente(ctx context.Context, id uint) (*Expediente, error) {
	inc, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	if err := assertScopeAccess(ctx, inc.Scope); err != nil {
		return nil, err
	}

	comentarios, _ := s.repo.ListComentarios(ctx, id)
	adjuntos, _ := s.repo.ListAdjuntos(ctx, id)
	medidas, _ := s.repo.ListMedidas(ctx, id)
	descargos, _ := s.repo.ListDescargos(ctx, id)
	resoluciones, _ := s.repo.ListResoluciones(ctx, id)
	apelaciones, _ := s.repo.ListApelaciones(ctx, id)
	notificaciones, _ := s.repo.ListNotificaciones(ctx, id)
	eventos, _ := s.repo.ListEventos(ctx, id)

	s.audit.log(ctx, "read_expediente", "incidencia", id, nil, nil)
	return &Expediente{
		Incidencia:     inc,
		Comentarios:    comentarios,
		Adjuntos:       adjuntos,
		Medidas:        medidas,
		Descargos:      descargos,
		Resoluciones:   resoluciones,
		Apelaciones:    apelaciones,
		Notificaciones: notificaciones,
		Eventos:        eventos,
	}, nil
}
