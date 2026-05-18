package domain_test

import (
	"testing"

	"github.com/MargonDiego/GOAPI/internal/domain"
	"github.com/stretchr/testify/assert"
)

func TestValidarRut(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		input    string
		wantNorm string
		wantErr  bool
	}{
		{"válido con puntos y guion", "12.345.678-5", "12345678-5", false},
		{"válido sin formato", "123456785", "12345678-5", false},
		{"válido DV K", "20.347.878-K", "20347878-K", false},
		{"válido DV k minúscula", "20347878k", "20347878-K", false},
		{"DV incorrecto", "12.345.678-9", "", true},
		{"cuerpo no numérico", "12A45678-5", "", true},
		{"vacío", "", "", true},
		{"solo DV", "5", "", true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			norm, err := domain.ValidarRut(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorIs(t, err, domain.ErrRutInvalido)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantNorm, norm)
			}
		})
	}
}

func TestNewEstudiante(t *testing.T) {
	t.Parallel()
	t.Run("crea con datos válidos", func(t *testing.T) {
		t.Parallel()
		e, err := domain.NewEstudiante("Juan Pérez", "8°B", "colegio-x")
		assert.NoError(t, err)
		assert.Equal(t, "Juan Pérez", e.Nombre)
		assert.Equal(t, "8°B", e.Curso)
		assert.Equal(t, "colegio-x", e.Scope)
	})
	t.Run("rechaza nombre vacío", func(t *testing.T) {
		t.Parallel()
		_, err := domain.NewEstudiante("  ", "8°B", "colegio-x")
		assert.ErrorIs(t, err, domain.ErrInvalidInput)
	})
	t.Run("rechaza curso vacío", func(t *testing.T) {
		t.Parallel()
		_, err := domain.NewEstudiante("Juan", "", "colegio-x")
		assert.ErrorIs(t, err, domain.ErrInvalidInput)
	})
}
