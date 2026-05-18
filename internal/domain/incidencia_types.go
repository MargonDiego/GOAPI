package domain

// EstadoIncidencia representa el estado en la máquina de estados del expediente.
type EstadoIncidencia string

const (
	EstadoRecibida        EstadoIncidencia = "RECIBIDA"
	EstadoEnInvestigacion EstadoIncidencia = "EN_INVESTIGACION"
	EstadoResuelta        EstadoIncidencia = "RESUELTA"
	EstadoEnApelacion     EstadoIncidencia = "EN_APELACION"
	EstadoResolucionFinal EstadoIncidencia = "RESOLUCION_FINAL"
	EstadoEnSeguimiento   EstadoIncidencia = "EN_SEGUIMIENTO"
	EstadoCerrada         EstadoIncidencia = "CERRADA"
	EstadoDerived         EstadoIncidencia = "DERIVADA"
)

// GravedadIncidencia clasifica la falta según Ley 20.536 y Ley 21.128.
type GravedadIncidencia string

const (
	GravedadLeve     GravedadIncidencia = "LEVE"
	GravedadGrave    GravedadIncidencia = "GRAVE"
	GravedadGravisima GravedadIncidencia = "GRAVISIMA"
)

// CategoriaIncidencia tipifica el hecho según la Política Nacional de Convivencia.
type CategoriaIncidencia string

const (
	CategoriaMaltratoEstudiantes CategoriaIncidencia = "maltrato_entre_estudiantes"
	CategoriaMaltratoAdulto      CategoriaIncidencia = "maltrato_adulto_estudiante"
	CategoriaCiberacoso          CategoriaIncidencia = "ciberacoso"
	CategoriaVulneracion         CategoriaIncidencia = "vulneracion_derechos"
	CategoriaConnotacionSexual   CategoriaIncidencia = "connotacion_sexual"
	CategoriaPorteArma           CategoriaIncidencia = "porte_arma"
	CategoriaConsumo             CategoriaIncidencia = "consumo"
	CategoriaOtro                CategoriaIncidencia = "otro"
)

// ClaseMedida distingue entre medidas formativas y disciplinarias (Ley 20.536).
type ClaseMedida string

const (
	ClaseFormativa   ClaseMedida = "FORMATIVA"
	ClaseDisciplinaria ClaseMedida = "DISCIPLINARIA"
)

// TipoMedida define las medidas disponibles según el RICE.
type TipoMedida string

const (
	TipoDialogo           TipoMedida = "dialogo"
	TipoServicioComunitario TipoMedida = "servicio"
	TipoSuspension        TipoMedida = "suspension"
	TipoCondicionalidad   TipoMedida = "condicionalidad"
	TipoCancelacion       TipoMedida = "cancelacion"
	TipoExpulsion         TipoMedida = "expulsion"
)

// EstadoCumplimiento refleja el seguimiento de una medida.
type EstadoCumplimiento string

const (
	CumplimientoPendiente  EstadoCumplimiento = "PENDIENTE"
	CumplimientoEnCurso    EstadoCumplimiento = "EN_CURSO"
	CumplimientoCumplida   EstadoCumplimiento = "CUMPLIDA"
	CumplimientoIncumplida EstadoCumplimiento = "INCUMPLIDA"
)

// TipoResolucion diferencia la resolución original de la que resuelve una apelación.
type TipoResolucion string

const (
	ResolucionOriginal  TipoResolucion = "ORIGINAL"
	ResolucionApelacion TipoResolucion = "APELACION"
)

// EstadoApelacion es el ciclo de vida de una apelación presentada.
type EstadoApelacion string

const (
	ApelacionPendiente  EstadoApelacion = "PENDIENTE"
	ApelacionAceptada   EstadoApelacion = "ACEPTADA"
	ApelacionRechazada  EstadoApelacion = "RECHAZADA"
)

// TipoEvento identifica el tipo de entrada en el historial legal inmutable.
type TipoEvento string

const (
	EventoCreacion      TipoEvento = "CREACION"
	EventoCambioEstado  TipoEvento = "CAMBIO_ESTADO"
	EventoAsignacion    TipoEvento = "ASIGNACION"
	EventoComentario    TipoEvento = "COMENTARIO"
	EventoAdjunto       TipoEvento = "ADJUNTO"
	EventoMedida        TipoEvento = "MEDIDA"
	EventoDescargo      TipoEvento = "DESCARGO"
	EventoResolucion    TipoEvento = "RESOLUCION"
	EventoApelacion     TipoEvento = "APELACION"
	EventoNotificacion  TipoEvento = "NOTIFICACION"
)

// IncidenciaFilter agrupa los criterios de búsqueda para incidencias.
type IncidenciaFilter struct {
	Estado        EstadoIncidencia
	Gravedad      GravedadIncidencia
	Categoria     CategoriaIncidencia
	ResponsableID *uint
	EstudianteID  *uint
	Scope         string
}
