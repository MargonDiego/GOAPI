package domain

import (
	"strings"
	"time"
)

// Comentario es un mensaje append-only del hilo de trabajo (inmutable).
type Comentario struct {
	ID           uint
	IncidenciaID uint
	AutorID      uint
	Cuerpo       string
	CreatedAt    time.Time
}

func NewComentario(incidenciaID, autorID uint, cuerpo string) (*Comentario, error) {
	cuerpo = strings.TrimSpace(cuerpo)
	if cuerpo == "" {
		return nil, ErrInvalidInput
	}
	return &Comentario{
		IncidenciaID: incidenciaID,
		AutorID:      autorID,
		Cuerpo:       cuerpo,
		CreatedAt:    time.Now(),
	}, nil
}

// Adjunto referencia un archivo almacenado fuera de la BD.
// NombreAlmacenado es el UUID generado por LocalFileStorage.
type Adjunto struct {
	ID               uint
	IncidenciaID     uint
	NombreOriginal   string
	NombreAlmacenado string
	MimeType         string
	TamanoBytes      int64
	HashSHA256       string
	SubidoPorID      uint
	CreatedAt        time.Time
}

// Medida es la sanción o medida formativa acordada.
// Proporcionalidad es obligatoria (base de juicio para auditorías Ley 20.536).
type Medida struct {
	ID                     uint
	IncidenciaID           uint
	Clase                  ClaseMedida
	Tipo                   TipoMedida
	Descripcion            string
	Proporcionalidad       string
	ResponsableEjecucionID uint
	FechaInicio            time.Time
	FechaTermino           *time.Time
	EstadoCumplimiento     EstadoCumplimiento
	CreatedAt              time.Time
}

// NewMedida valida que la proporcionalidad esté documentada.
// La restricción expulsion/cancelacion solo GRAVISIMA se valida en el servicio
// porque requiere conocer la Gravedad de la Incidencia raíz.
func NewMedida(incidenciaID uint, clase ClaseMedida, tipo TipoMedida, descripcion, proporcionalidad string, responsableEjecID uint, fechaInicio time.Time, fechaTermino *time.Time) (*Medida, error) {
	if strings.TrimSpace(proporcionalidad) == "" {
		return nil, ErrMedidaDesproporcionada
	}
	return &Medida{
		IncidenciaID:           incidenciaID,
		Clase:                  clase,
		Tipo:                   tipo,
		Descripcion:            descripcion,
		Proporcionalidad:       proporcionalidad,
		ResponsableEjecucionID: responsableEjecID,
		FechaInicio:            fechaInicio,
		FechaTermino:           fechaTermino,
		EstadoCumplimiento:     CumplimientoPendiente,
		CreatedAt:              time.Now(),
	}, nil
}

// Descargo es el derecho a ser oído del involucrado (debido proceso).
type Descargo struct {
	ID                uint
	IncidenciaID      uint
	PresentadoPorID   uint
	Contenido         string
	FechaPresentacion time.Time
	CreatedAt         time.Time
}

func NewDescargo(incidenciaID, presentadoPorID uint, contenido string) (*Descargo, error) {
	contenido = strings.TrimSpace(contenido)
	if contenido == "" {
		return nil, ErrInvalidInput
	}
	now := time.Now()
	return &Descargo{
		IncidenciaID:      incidenciaID,
		PresentadoPorID:   presentadoPorID,
		Contenido:         contenido,
		FechaPresentacion: now,
		CreatedAt:         now,
	}, nil
}

// Resolucion es la decisión motivada. Fundamentacion no puede estar vacía.
type Resolucion struct {
	ID              uint
	IncidenciaID    uint
	Tipo            TipoResolucion
	Fundamentacion  string
	Decision        string
	ResueltoPorID   uint
	FechaResolucion time.Time
	CreatedAt       time.Time
}

func NewResolucion(incidenciaID uint, tipo TipoResolucion, fundamentacion, decision string, resueltoPorID uint) (*Resolucion, error) {
	if strings.TrimSpace(fundamentacion) == "" {
		return nil, ErrResolucionSinFundamento
	}
	now := time.Now()
	return &Resolucion{
		IncidenciaID:    incidenciaID,
		Tipo:            tipo,
		Fundamentacion:  fundamentacion,
		Decision:        decision,
		ResueltoPorID:   resueltoPorID,
		FechaResolucion: now,
		CreatedAt:       now,
	}, nil
}

// Apelacion representa el recurso de apelación presentado contra una resolución.
type Apelacion struct {
	ID                uint
	IncidenciaID      uint
	ResolucionID      uint
	PresentadaPorID   uint
	Motivo            string
	FechaPresentacion time.Time
	PlazoVencimiento  time.Time
	Estado            EstadoApelacion
	CreatedAt         time.Time
}

func NewApelacion(incidenciaID, resolucionID, presentadaPorID uint, motivo string, plazoVencimiento time.Time) (*Apelacion, error) {
	now := time.Now()
	return &Apelacion{
		IncidenciaID:      incidenciaID,
		ResolucionID:      resolucionID,
		PresentadaPorID:   presentadaPorID,
		Motivo:            motivo,
		FechaPresentacion: now,
		PlazoVencimiento:  plazoVencimiento,
		Estado:            ApelacionPendiente,
		CreatedAt:         now,
	}, nil
}

// Notificacion al apoderado con control de acuse de recibo (debido proceso).
type Notificacion struct {
	ID                uint
	IncidenciaID      uint
	Destinatario      string
	Medio             string
	Contenido         string
	FechaNotificacion time.Time
	Acuse             bool
	FechaAcuse        *time.Time
	CreatedAt         time.Time
}

func NewNotificacion(incidenciaID uint, destinatario, medio, contenido string, fecha time.Time) (*Notificacion, error) {
	now := time.Now()
	return &Notificacion{
		IncidenciaID:      incidenciaID,
		Destinatario:      destinatario,
		Medio:             medio,
		Contenido:         contenido,
		FechaNotificacion: fecha,
		Acuse:             false,
		CreatedAt:         now,
	}, nil
}

// IncidenciaEvento es el historial legal inmutable del expediente.
// SIN IP ni User-Agent (eso va en AuditLog) — retención diferenciada Ley 21.719.
type IncidenciaEvento struct {
	ID             uint
	IncidenciaID   uint
	Tipo           TipoEvento
	ActorID        uint
	Resumen        string
	EstadoAnterior *EstadoIncidencia
	EstadoNuevo    *EstadoIncidencia
	CreatedAt      time.Time
}

func NewIncidenciaEvento(incidenciaID uint, tipo TipoEvento, actorID uint, resumen string, anterior, nuevo *EstadoIncidencia) *IncidenciaEvento {
	return &IncidenciaEvento{
		IncidenciaID:   incidenciaID,
		Tipo:           tipo,
		ActorID:        actorID,
		Resumen:        resumen,
		EstadoAnterior: anterior,
		EstadoNuevo:    nuevo,
		CreatedAt:      time.Now(),
	}
}
