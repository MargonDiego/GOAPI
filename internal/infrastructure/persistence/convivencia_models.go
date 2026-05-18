package persistence

import (
	"time"

	"github.com/MargonDiego/GOAPI/internal/domain"
	"gorm.io/gorm"
)

// Estudiante es el modelo de persistencia (separado de la entidad de dominio).
type Estudiante struct {
	gorm.Model
	RutHash         string `gorm:"column:rut_hash;uniqueIndex;not null"`
	RutEncrypted    string `gorm:"column:rut_encrypted;not null"`
	NombreEncrypted string `gorm:"column:nombre_encrypted;not null"`
	Curso           string `gorm:"column:curso;index;not null"`
	Scope           string `gorm:"column:scope;index;not null;default:''"`
}

func (Estudiante) TableName() string { return "estudiantes" }

func toDomainEstudiante(e *Estudiante) *domain.Estudiante {
	if e == nil {
		return nil
	}
	return &domain.Estudiante{
		ID:              e.ID,
		RutHash:         e.RutHash,
		RutEncrypted:    e.RutEncrypted,
		NombreEncrypted: e.NombreEncrypted,
		Curso:           e.Curso,
		Scope:           e.Scope,
	}
}

func toDBEstudiante(d *domain.Estudiante) *Estudiante {
	if d == nil {
		return nil
	}
	e := &Estudiante{
		RutHash:         d.RutHash,
		RutEncrypted:    d.RutEncrypted,
		NombreEncrypted: d.NombreEncrypted,
		Curso:           d.Curso,
		Scope:           d.Scope,
	}
	if d.ID != 0 {
		e.ID = d.ID
	}
	return e
}

// ---------------------------------------------------------------------------
// Incidencia
// ---------------------------------------------------------------------------

type IncidenciaDB struct {
	gorm.Model
	Codigo                     string     `gorm:"column:codigo;not null"`
	EstudianteID               uint       `gorm:"column:estudiante_id;not null"`
	Titulo                     string     `gorm:"column:titulo;not null"`
	Descripcion                string     `gorm:"column:descripcion;not null;default:''"`
	Gravedad                   string     `gorm:"column:gravedad;not null"`
	Categoria                  string     `gorm:"column:categoria;not null"`
	EsConstitutivoDeDelito     bool       `gorm:"column:es_constitutivo_de_delito;not null;default:false"`
	Estado                     string     `gorm:"column:estado;not null;default:'RECIBIDA'"`
	DenuncianteID              uint       `gorm:"column:denunciante_id;not null"`
	ResponsableID              *uint      `gorm:"column:responsable_id"`
	Scope                      string     `gorm:"column:scope;not null;default:''"`
	SuspensionPreventiva       bool       `gorm:"column:suspension_preventiva;not null;default:false"`
	FechaSuspensionPreventiva  *time.Time `gorm:"column:fecha_suspension_preventiva"`
	FechaRecepcion             time.Time  `gorm:"column:fecha_recepcion;not null"`
	FechaInicioInvestigacion   *time.Time `gorm:"column:fecha_inicio_investigacion"`
	FechaCierre                *time.Time `gorm:"column:fecha_cierre"`
	FechaEliminacionProgramada *time.Time `gorm:"column:fecha_eliminacion_programada"`
}

func (IncidenciaDB) TableName() string { return "incidencias" }

func toDomainIncidencia(m *IncidenciaDB) *domain.Incidencia {
	if m == nil {
		return nil
	}
	return &domain.Incidencia{
		ID:                         m.ID,
		Codigo:                     m.Codigo,
		EstudianteID:               m.EstudianteID,
		Titulo:                     m.Titulo,
		Descripcion:                m.Descripcion,
		Gravedad:                   domain.GravedadIncidencia(m.Gravedad),
		Categoria:                  domain.CategoriaIncidencia(m.Categoria),
		EsConstitutivoDeDelito:     m.EsConstitutivoDeDelito,
		Estado:                     domain.EstadoIncidencia(m.Estado),
		DenuncianteID:              m.DenuncianteID,
		ResponsableID:              m.ResponsableID,
		Scope:                      m.Scope,
		SuspensionPreventiva:       m.SuspensionPreventiva,
		FechaSuspensionPreventiva:  m.FechaSuspensionPreventiva,
		FechaRecepcion:             m.FechaRecepcion,
		FechaInicioInvestigacion:   m.FechaInicioInvestigacion,
		FechaCierre:                m.FechaCierre,
		FechaEliminacionProgramada: m.FechaEliminacionProgramada,
	}
}

func toDBIncidencia(d *domain.Incidencia) *IncidenciaDB {
	m := &IncidenciaDB{
		Codigo:                     d.Codigo,
		EstudianteID:               d.EstudianteID,
		Titulo:                     d.Titulo,
		Descripcion:                d.Descripcion,
		Gravedad:                   string(d.Gravedad),
		Categoria:                  string(d.Categoria),
		EsConstitutivoDeDelito:     d.EsConstitutivoDeDelito,
		Estado:                     string(d.Estado),
		DenuncianteID:              d.DenuncianteID,
		ResponsableID:              d.ResponsableID,
		Scope:                      d.Scope,
		SuspensionPreventiva:       d.SuspensionPreventiva,
		FechaSuspensionPreventiva:  d.FechaSuspensionPreventiva,
		FechaRecepcion:             d.FechaRecepcion,
		FechaInicioInvestigacion:   d.FechaInicioInvestigacion,
		FechaCierre:                d.FechaCierre,
		FechaEliminacionProgramada: d.FechaEliminacionProgramada,
	}
	if d.ID != 0 {
		m.ID = d.ID
	}
	return m
}

// ---------------------------------------------------------------------------
// Comentario
// ---------------------------------------------------------------------------

type ComentarioDB struct {
	ID           uint      `gorm:"primaryKey;autoIncrement"`
	IncidenciaID uint      `gorm:"column:incidencia_id;not null"`
	AutorID      uint      `gorm:"column:autor_id;not null"`
	Cuerpo       string    `gorm:"column:cuerpo;not null"`
	CreatedAt    time.Time `gorm:"column:created_at;not null;autoCreateTime"`
}

func (ComentarioDB) TableName() string { return "comentarios" }

func toDomainComentario(m ComentarioDB) domain.Comentario {
	return domain.Comentario{ID: m.ID, IncidenciaID: m.IncidenciaID, AutorID: m.AutorID, Cuerpo: m.Cuerpo, CreatedAt: m.CreatedAt}
}

// ---------------------------------------------------------------------------
// Adjunto
// ---------------------------------------------------------------------------

type AdjuntoDB struct {
	ID               uint      `gorm:"primaryKey;autoIncrement"`
	IncidenciaID     uint      `gorm:"column:incidencia_id;not null"`
	NombreOriginal   string    `gorm:"column:nombre_original;not null"`
	NombreAlmacenado string    `gorm:"column:nombre_almacenado;not null;uniqueIndex"`
	MimeType         string    `gorm:"column:mime_type;not null;default:''"`
	TamanoBytes      int64     `gorm:"column:tamano_bytes;not null;default:0"`
	HashSHA256       string    `gorm:"column:hash_sha256;not null;default:''"`
	SubidoPorID      uint      `gorm:"column:subido_por_id;not null"`
	CreatedAt        time.Time `gorm:"column:created_at;not null;autoCreateTime"`
}

func (AdjuntoDB) TableName() string { return "adjuntos" }

func toDomainAdjunto(m AdjuntoDB) domain.Adjunto {
	return domain.Adjunto{ID: m.ID, IncidenciaID: m.IncidenciaID, NombreOriginal: m.NombreOriginal, NombreAlmacenado: m.NombreAlmacenado, MimeType: m.MimeType, TamanoBytes: m.TamanoBytes, HashSHA256: m.HashSHA256, SubidoPorID: m.SubidoPorID, CreatedAt: m.CreatedAt}
}

// ---------------------------------------------------------------------------
// Medida
// ---------------------------------------------------------------------------

type MedidaDB struct {
	ID                     uint       `gorm:"primaryKey;autoIncrement"`
	IncidenciaID           uint       `gorm:"column:incidencia_id;not null"`
	Clase                  string     `gorm:"column:clase;not null"`
	Tipo                   string     `gorm:"column:tipo;not null"`
	Descripcion            string     `gorm:"column:descripcion;not null;default:''"`
	Proporcionalidad       string     `gorm:"column:proporcionalidad;not null;default:''"`
	ResponsableEjecucionID uint       `gorm:"column:responsable_ejecucion_id;not null"`
	FechaInicio            time.Time  `gorm:"column:fecha_inicio"`
	FechaTermino           *time.Time `gorm:"column:fecha_termino"`
	EstadoCumplimiento     string     `gorm:"column:estado_cumplimiento;not null;default:'PENDIENTE'"`
	CreatedAt              time.Time  `gorm:"column:created_at;not null;autoCreateTime"`
}

func (MedidaDB) TableName() string { return "medidas" }

func toDomainMedida(m MedidaDB) domain.Medida {
	return domain.Medida{ID: m.ID, IncidenciaID: m.IncidenciaID, Clase: domain.ClaseMedida(m.Clase), Tipo: domain.TipoMedida(m.Tipo), Descripcion: m.Descripcion, Proporcionalidad: m.Proporcionalidad, ResponsableEjecucionID: m.ResponsableEjecucionID, FechaInicio: m.FechaInicio, FechaTermino: m.FechaTermino, EstadoCumplimiento: domain.EstadoCumplimiento(m.EstadoCumplimiento), CreatedAt: m.CreatedAt}
}

// ---------------------------------------------------------------------------
// Descargo
// ---------------------------------------------------------------------------

type DescargoDB struct {
	ID                uint      `gorm:"primaryKey;autoIncrement"`
	IncidenciaID      uint      `gorm:"column:incidencia_id;not null"`
	PresentadoPorID   uint      `gorm:"column:presentado_por_id;not null"`
	Contenido         string    `gorm:"column:contenido;not null;default:''"`
	FechaPresentacion time.Time `gorm:"column:fecha_presentacion;not null"`
	CreatedAt         time.Time `gorm:"column:created_at;not null;autoCreateTime"`
}

func (DescargoDB) TableName() string { return "descargos" }

func toDomainDescargo(m DescargoDB) domain.Descargo {
	return domain.Descargo{ID: m.ID, IncidenciaID: m.IncidenciaID, PresentadoPorID: m.PresentadoPorID, Contenido: m.Contenido, FechaPresentacion: m.FechaPresentacion, CreatedAt: m.CreatedAt}
}

// ---------------------------------------------------------------------------
// Resolucion
// ---------------------------------------------------------------------------

type ResolucionDB struct {
	ID              uint      `gorm:"primaryKey;autoIncrement"`
	IncidenciaID    uint      `gorm:"column:incidencia_id;not null"`
	Tipo            string    `gorm:"column:tipo;not null;default:'ORIGINAL'"`
	Fundamentacion  string    `gorm:"column:fundamentacion;not null;default:''"`
	Decision        string    `gorm:"column:decision;not null;default:''"`
	ResueltoPorID   uint      `gorm:"column:resuelto_por_id;not null"`
	FechaResolucion time.Time `gorm:"column:fecha_resolucion;not null"`
	CreatedAt       time.Time `gorm:"column:created_at;not null;autoCreateTime"`
}

func (ResolucionDB) TableName() string { return "resoluciones" }

func toDomainResolucion(m ResolucionDB) domain.Resolucion {
	return domain.Resolucion{ID: m.ID, IncidenciaID: m.IncidenciaID, Tipo: domain.TipoResolucion(m.Tipo), Fundamentacion: m.Fundamentacion, Decision: m.Decision, ResueltoPorID: m.ResueltoPorID, FechaResolucion: m.FechaResolucion, CreatedAt: m.CreatedAt}
}

// ---------------------------------------------------------------------------
// Apelacion
// ---------------------------------------------------------------------------

type ApelacionDB struct {
	ID                uint      `gorm:"primaryKey;autoIncrement"`
	IncidenciaID      uint      `gorm:"column:incidencia_id;not null"`
	ResolucionID      uint      `gorm:"column:resolucion_id;not null"`
	PresentadaPorID   uint      `gorm:"column:presentada_por_id;not null"`
	Motivo            string    `gorm:"column:motivo;not null;default:''"`
	FechaPresentacion time.Time `gorm:"column:fecha_presentacion;not null"`
	PlazoVencimiento  time.Time `gorm:"column:plazo_vencimiento;not null"`
	Estado            string    `gorm:"column:estado;not null;default:'PENDIENTE'"`
	CreatedAt         time.Time `gorm:"column:created_at;not null;autoCreateTime"`
}

func (ApelacionDB) TableName() string { return "apelaciones" }

func toDomainApelacion(m ApelacionDB) domain.Apelacion {
	return domain.Apelacion{ID: m.ID, IncidenciaID: m.IncidenciaID, ResolucionID: m.ResolucionID, PresentadaPorID: m.PresentadaPorID, Motivo: m.Motivo, FechaPresentacion: m.FechaPresentacion, PlazoVencimiento: m.PlazoVencimiento, Estado: domain.EstadoApelacion(m.Estado), CreatedAt: m.CreatedAt}
}

// ---------------------------------------------------------------------------
// Notificacion
// ---------------------------------------------------------------------------

type NotificacionDB struct {
	ID                uint       `gorm:"primaryKey;autoIncrement"`
	IncidenciaID      uint       `gorm:"column:incidencia_id;not null"`
	Destinatario      string     `gorm:"column:destinatario;not null;default:''"`
	Medio             string     `gorm:"column:medio;not null;default:''"`
	Contenido         string     `gorm:"column:contenido;not null;default:''"`
	FechaNotificacion time.Time  `gorm:"column:fecha_notificacion;not null"`
	Acuse             bool       `gorm:"column:acuse;not null;default:false"`
	FechaAcuse        *time.Time `gorm:"column:fecha_acuse"`
	CreatedAt         time.Time  `gorm:"column:created_at;not null;autoCreateTime"`
}

func (NotificacionDB) TableName() string { return "notificaciones" }

func toDomainNotificacion(m NotificacionDB) domain.Notificacion {
	return domain.Notificacion{ID: m.ID, IncidenciaID: m.IncidenciaID, Destinatario: m.Destinatario, Medio: m.Medio, Contenido: m.Contenido, FechaNotificacion: m.FechaNotificacion, Acuse: m.Acuse, FechaAcuse: m.FechaAcuse, CreatedAt: m.CreatedAt}
}

// ---------------------------------------------------------------------------
// IncidenciaEvento (historial legal inmutable)
// ---------------------------------------------------------------------------

type IncidenciaEventoDB struct {
	ID             uint                      `gorm:"primaryKey;autoIncrement"`
	IncidenciaID   uint                      `gorm:"column:incidencia_id;not null"`
	Tipo           string                    `gorm:"column:tipo;not null"`
	ActorID        uint                      `gorm:"column:actor_id;not null"`
	Resumen        string                    `gorm:"column:resumen;not null;default:''"`
	EstadoAnterior *domain.EstadoIncidencia  `gorm:"column:estado_anterior"`
	EstadoNuevo    *domain.EstadoIncidencia  `gorm:"column:estado_nuevo"`
	CreatedAt      time.Time                 `gorm:"column:created_at;not null;autoCreateTime"`
}

func (IncidenciaEventoDB) TableName() string { return "incidencia_eventos" }

func toDomainEvento(m IncidenciaEventoDB) domain.IncidenciaEvento {
	return domain.IncidenciaEvento{ID: m.ID, IncidenciaID: m.IncidenciaID, Tipo: domain.TipoEvento(m.Tipo), ActorID: m.ActorID, Resumen: m.Resumen, EstadoAnterior: m.EstadoAnterior, EstadoNuevo: m.EstadoNuevo, CreatedAt: m.CreatedAt}
}
