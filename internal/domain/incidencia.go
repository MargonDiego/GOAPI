package domain

import (
	"strings"
	"time"
)

// Incidencia es la raíz del agregado de convivencia escolar.
// La máquina de estados vive en el dominio: las guardas son métodos puros.
// El servicio de aplicación orquesta la persistencia y los eventos.
type Incidencia struct {
	ID                         uint
	Codigo                     string
	EstudianteID               uint
	Titulo                     string
	Descripcion                string
	Gravedad                   GravedadIncidencia
	Categoria                  CategoriaIncidencia
	EsConstitutivoDeDelito     bool
	Estado                     EstadoIncidencia
	DenuncianteID              uint
	ResponsableID              *uint
	Scope                      string
	SuspensionPreventiva       bool
	FechaSuspensionPreventiva  *time.Time
	FechaRecepcion             time.Time
	FechaInicioInvestigacion   *time.Time
	FechaCierre                *time.Time
	FechaEliminacionProgramada *time.Time
}

// NewIncidencia crea una incidencia en estado RECIBIDA validando invariantes mínimos.
func NewIncidencia(titulo, descripcion string, gravedad GravedadIncidencia, categoria CategoriaIncidencia, estudianteID, denuncianteID uint, scope string) (*Incidencia, error) {
	titulo = strings.TrimSpace(titulo)
	if titulo == "" {
		return nil, ErrInvalidInput
	}
	if estudianteID == 0 {
		return nil, ErrInvalidInput
	}
	return &Incidencia{
		Titulo:         titulo,
		Descripcion:    descripcion,
		Gravedad:       gravedad,
		Categoria:      categoria,
		EstudianteID:   estudianteID,
		DenuncianteID:  denuncianteID,
		Scope:          scope,
		Estado:         EstadoRecibida,
		FechaRecepcion: time.Now(),
	}, nil
}

// IniciarInvestigacion: RECIBIDA → EN_INVESTIGACION.
// Requiere responsable asignado y fecha de inicio.
func (i *Incidencia) IniciarInvestigacion(responsableID uint, fecha time.Time) error {
	if i.Estado != EstadoRecibida {
		return ErrTransicionInvalida
	}
	i.Estado = EstadoEnInvestigacion
	i.ResponsableID = &responsableID
	i.FechaInicioInvestigacion = &fecha
	return nil
}

// Resolver: EN_INVESTIGACION → RESUELTA.
// El servicio valida que exista al menos una Resolucion con Fundamentacion antes de llamar este método.
func (i *Incidencia) Resolver() error {
	if i.Estado != EstadoEnInvestigacion {
		return ErrTransicionInvalida
	}
	i.Estado = EstadoResuelta
	return nil
}

// IniciarApelacion: RESUELTA → EN_APELACION.
func (i *Incidencia) IniciarApelacion() error {
	if i.Estado != EstadoResuelta {
		return ErrTransicionInvalida
	}
	i.Estado = EstadoEnApelacion
	return nil
}

// ResolverApelacion: EN_APELACION → RESOLUCION_FINAL.
func (i *Incidencia) ResolverApelacion() error {
	if i.Estado != EstadoEnApelacion {
		return ErrTransicionInvalida
	}
	i.Estado = EstadoResolucionFinal
	return nil
}

// IniciarSeguimiento: RESUELTA | RESOLUCION_FINAL → EN_SEGUIMIENTO.
func (i *Incidencia) IniciarSeguimiento() error {
	if i.Estado != EstadoResuelta && i.Estado != EstadoResolucionFinal {
		return ErrTransicionInvalida
	}
	i.Estado = EstadoEnSeguimiento
	return nil
}

// Cerrar: EN_SEGUIMIENTO → CERRADA.
// El servicio verifica que no haya apelaciones PENDIENTE antes de llamar este método.
func (i *Incidencia) Cerrar() error {
	if i.Estado != EstadoEnSeguimiento {
		return ErrTransicionInvalida
	}
	now := time.Now()
	i.Estado = EstadoCerrada
	i.FechaCierre = &now
	return nil
}

// Derivar: RECIBIDA | EN_INVESTIGACION → DERIVADA.
func (i *Incidencia) Derivar() error {
	if i.Estado != EstadoRecibida && i.Estado != EstadoEnInvestigacion {
		return ErrTransicionInvalida
	}
	i.Estado = EstadoDerived
	return nil
}
