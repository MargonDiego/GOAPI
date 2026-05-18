package domain_test

import (
	"testing"
	"time"

	"github.com/MargonDiego/GOAPI/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewIncidencia(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		titulo      string
		desc        string
		gravedad    domain.GravedadIncidencia
		categoria   domain.CategoriaIncidencia
		estudianteID uint
		denuncianteID uint
		scope       string
		wantErr     bool
	}{
		{
			name: "incidencia valida",
			titulo: "Pelea en recreo",
			desc: "Descripcion del incidente",
			gravedad: domain.GravedadGrave,
			categoria: domain.CategoriaMaltratoEstudiantes,
			estudianteID: 1,
			denuncianteID: 2,
			scope: "colegio-a",
		},
		{
			name:    "titulo vacio rechazado",
			titulo:  "",
			gravedad: domain.GravedadLeve,
			categoria: domain.CategoriaOtro,
			estudianteID: 1,
			denuncianteID: 1,
			wantErr: true,
		},
		{
			name:    "sin estudianteID rechazado",
			titulo:  "Incidente",
			gravedad: domain.GravedadLeve,
			categoria: domain.CategoriaOtro,
			estudianteID: 0,
			denuncianteID: 1,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			inc, err := domain.NewIncidencia(tc.titulo, tc.desc, tc.gravedad, tc.categoria, tc.estudianteID, tc.denuncianteID, tc.scope)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, domain.EstadoRecibida, inc.Estado)
			assert.Equal(t, tc.titulo, inc.Titulo)
			assert.Equal(t, tc.gravedad, inc.Gravedad)
			assert.False(t, inc.FechaRecepcion.IsZero())
		})
	}
}

func TestIncidencia_MaquinaEstados(t *testing.T) {
	t.Parallel()

	newInc := func() *domain.Incidencia {
		inc, err := domain.NewIncidencia("Test", "desc", domain.GravedadGrave, domain.CategoriaOtro, 1, 2, "scope")
		require.NoError(t, err)
		return inc
	}

	t.Run("IniciarInvestigacion requiere RECIBIDA", func(t *testing.T) {
		t.Parallel()
		inc := newInc()
		require.NoError(t, inc.IniciarInvestigacion(10, time.Now()))
		assert.Equal(t, domain.EstadoEnInvestigacion, inc.Estado)
		assert.NotNil(t, inc.ResponsableID)
		assert.Equal(t, uint(10), *inc.ResponsableID)

		// segunda llamada falla
		err := inc.IniciarInvestigacion(10, time.Now())
		assert.ErrorIs(t, err, domain.ErrTransicionInvalida)
	})

	t.Run("Resolver requiere EN_INVESTIGACION", func(t *testing.T) {
		t.Parallel()
		inc := newInc()
		err := inc.Resolver()
		assert.ErrorIs(t, err, domain.ErrTransicionInvalida)

		require.NoError(t, inc.IniciarInvestigacion(1, time.Now()))
		require.NoError(t, inc.Resolver())
		assert.Equal(t, domain.EstadoResuelta, inc.Estado)
	})

	t.Run("IniciarApelacion requiere RESUELTA", func(t *testing.T) {
		t.Parallel()
		inc := newInc()
		require.NoError(t, inc.IniciarInvestigacion(1, time.Now()))
		require.NoError(t, inc.Resolver())
		require.NoError(t, inc.IniciarApelacion())
		assert.Equal(t, domain.EstadoEnApelacion, inc.Estado)

		err := inc.IniciarApelacion()
		assert.ErrorIs(t, err, domain.ErrTransicionInvalida)
	})

	t.Run("ResolverApelacion requiere EN_APELACION", func(t *testing.T) {
		t.Parallel()
		inc := newInc()
		require.NoError(t, inc.IniciarInvestigacion(1, time.Now()))
		require.NoError(t, inc.Resolver())
		require.NoError(t, inc.IniciarApelacion())
		require.NoError(t, inc.ResolverApelacion())
		assert.Equal(t, domain.EstadoResolucionFinal, inc.Estado)
	})

	t.Run("IniciarSeguimiento desde RESUELTA", func(t *testing.T) {
		t.Parallel()
		inc := newInc()
		require.NoError(t, inc.IniciarInvestigacion(1, time.Now()))
		require.NoError(t, inc.Resolver())
		require.NoError(t, inc.IniciarSeguimiento())
		assert.Equal(t, domain.EstadoEnSeguimiento, inc.Estado)
	})

	t.Run("IniciarSeguimiento desde RESOLUCION_FINAL", func(t *testing.T) {
		t.Parallel()
		inc := newInc()
		require.NoError(t, inc.IniciarInvestigacion(1, time.Now()))
		require.NoError(t, inc.Resolver())
		require.NoError(t, inc.IniciarApelacion())
		require.NoError(t, inc.ResolverApelacion())
		require.NoError(t, inc.IniciarSeguimiento())
		assert.Equal(t, domain.EstadoEnSeguimiento, inc.Estado)
	})

	t.Run("Cerrar requiere EN_SEGUIMIENTO y setea FechaCierre", func(t *testing.T) {
		t.Parallel()
		inc := newInc()
		require.NoError(t, inc.IniciarInvestigacion(1, time.Now()))
		require.NoError(t, inc.Resolver())
		require.NoError(t, inc.IniciarSeguimiento())
		require.NoError(t, inc.Cerrar())
		assert.Equal(t, domain.EstadoCerrada, inc.Estado)
		assert.NotNil(t, inc.FechaCierre)
	})

	t.Run("Derivar desde RECIBIDA o EN_INVESTIGACION", func(t *testing.T) {
		t.Parallel()
		inc := newInc()
		require.NoError(t, inc.Derivar())
		assert.Equal(t, domain.EstadoDerived, inc.Estado)

		inc2 := newInc()
		require.NoError(t, inc2.IniciarInvestigacion(1, time.Now()))
		require.NoError(t, inc2.Derivar())
		assert.Equal(t, domain.EstadoDerived, inc2.Estado)

		inc3 := newInc()
		require.NoError(t, inc3.IniciarInvestigacion(1, time.Now()))
		require.NoError(t, inc3.Resolver())
		err := inc3.Derivar()
		assert.ErrorIs(t, err, domain.ErrTransicionInvalida)
	})
}
