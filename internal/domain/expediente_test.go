package domain_test

import (
	"testing"
	"time"

	"github.com/MargonDiego/GOAPI/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewResolucion_FundamentacionObligatoria(t *testing.T) {
	t.Parallel()
	_, err := domain.NewResolucion(1, domain.ResolucionOriginal, "", "decision", 5)
	assert.ErrorIs(t, err, domain.ErrResolucionSinFundamento)

	_, err = domain.NewResolucion(1, domain.ResolucionOriginal, "   ", "decision", 5)
	assert.ErrorIs(t, err, domain.ErrResolucionSinFundamento)

	r, err := domain.NewResolucion(1, domain.ResolucionOriginal, "Se investigó y concluye...", "Se aplica medida formativa", 5)
	require.NoError(t, err)
	assert.Equal(t, domain.ResolucionOriginal, r.Tipo)
	assert.Equal(t, uint(1), r.IncidenciaID)
}

func TestNewMedida_ProporcionalidadObligatoria(t *testing.T) {
	t.Parallel()
	_, err := domain.NewMedida(1, domain.ClaseFormativa, domain.TipoDialogo, "desc", "", 3, time.Now(), nil)
	assert.ErrorIs(t, err, domain.ErrMedidaDesproporcionada)

	m, err := domain.NewMedida(1, domain.ClaseDisciplinaria, domain.TipoSuspension, "desc", "proporcional al hecho", 3, time.Now(), nil)
	require.NoError(t, err)
	assert.Equal(t, domain.CumplimientoPendiente, m.EstadoCumplimiento)
}

func TestNewApelacion(t *testing.T) {
	t.Parallel()
	plazo := time.Now().Add(5 * 24 * time.Hour)
	a, err := domain.NewApelacion(1, 2, 10, "motivo de apelacion", plazo)
	require.NoError(t, err)
	assert.Equal(t, domain.ApelacionPendiente, a.Estado)
	assert.Equal(t, uint(10), a.PresentadaPorID)
}

func TestNewComentario(t *testing.T) {
	t.Parallel()
	c, err := domain.NewComentario(1, 2, "cuerpo del comentario")
	require.NoError(t, err)
	assert.Equal(t, uint(1), c.IncidenciaID)
	assert.Equal(t, "cuerpo del comentario", c.Cuerpo)

	_, err = domain.NewComentario(1, 2, "")
	assert.Error(t, err)
}

func TestNewDescargo(t *testing.T) {
	t.Parallel()
	d, err := domain.NewDescargo(1, 5, "Mi descargo formal")
	require.NoError(t, err)
	assert.Equal(t, uint(5), d.PresentadoPorID)

	_, err = domain.NewDescargo(1, 5, "")
	assert.Error(t, err)
}

func TestNewNotificacion(t *testing.T) {
	t.Parallel()
	n, err := domain.NewNotificacion(1, "Apoderado Juan", "presencial", "Se notifica resolución", time.Now())
	require.NoError(t, err)
	assert.False(t, n.Acuse)
	assert.Nil(t, n.FechaAcuse)
}

func TestNewIncidenciaEvento(t *testing.T) {
	t.Parallel()
	e := domain.NewIncidenciaEvento(1, domain.EventoCreacion, 2, "Incidencia creada", nil, nil)
	assert.Equal(t, domain.EventoCreacion, e.Tipo)
	assert.Nil(t, e.EstadoAnterior)
	assert.Nil(t, e.EstadoNuevo)
}
