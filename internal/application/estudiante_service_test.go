package application_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/MargonDiego/GOAPI/internal/application"
	"github.com/MargonDiego/GOAPI/internal/domain"
	appcrypto "github.com/MargonDiego/GOAPI/internal/infrastructure/crypto"
	"github.com/MargonDiego/GOAPI/mocks"
)

func encForEstudiante(t *testing.T) *appcrypto.Encryptor {
	t.Helper()
	enc, err := appcrypto.NewEncryptor([]byte("12345678901234567890123456789012"))
	assert.NoError(t, err)
	return enc
}

func TestEstudianteService_Create(t *testing.T) {
	t.Parallel()

	t.Run("crea estudiante con RUT válido", func(t *testing.T) {
		t.Parallel()
		repo := mocks.NewMockEstudianteRepository(t)
		repo.On("FindByRutHash", mock.Anything, mock.Anything).Return(nil, domain.ErrEstudianteNotFound)
		repo.On("Create", mock.Anything, mock.AnythingOfType("*domain.Estudiante")).Return(nil)

		svc := application.NewEstudianteService(repo, encForEstudiante(t), nil)
		ctx := application.WithScope(context.Background(), "colegio-x")

		err := svc.Create(ctx, "12.345.678-5", "Juan Pérez", "8°B")
		assert.NoError(t, err)
	})

	t.Run("rechaza RUT inválido", func(t *testing.T) {
		t.Parallel()
		repo := mocks.NewMockEstudianteRepository(t)
		svc := application.NewEstudianteService(repo, encForEstudiante(t), nil)
		ctx := application.WithScope(context.Background(), "colegio-x")

		err := svc.Create(ctx, "12.345.678-9", "Juan", "8°B")
		assert.ErrorIs(t, err, domain.ErrRutInvalido)
	})

	t.Run("rechaza RUT duplicado", func(t *testing.T) {
		t.Parallel()
		repo := mocks.NewMockEstudianteRepository(t)
		repo.On("FindByRutHash", mock.Anything, mock.Anything).
			Return(&domain.Estudiante{ID: 1}, nil)

		svc := application.NewEstudianteService(repo, encForEstudiante(t), nil)
		ctx := application.WithScope(context.Background(), "colegio-x")

		err := svc.Create(ctx, "12.345.678-5", "Juan", "8°B")
		assert.ErrorIs(t, err, domain.ErrInvalidInput)
	})
}

func TestEstudianteService_GetByID(t *testing.T) {
	t.Parallel()
	enc := encForEstudiante(t)
	rutCt, _ := enc.Encrypt("12345678-5")
	nomCt, _ := enc.Encrypt("Juan Pérez")

	repo := mocks.NewMockEstudianteRepository(t)
	repo.On("FindByID", mock.Anything, uint(1)).Return(&domain.Estudiante{
		ID: 1, RutEncrypted: rutCt, NombreEncrypted: nomCt, Curso: "8°B", Scope: "colegio-x",
	}, nil)

	svc := application.NewEstudianteService(repo, enc, nil)
	ctx := application.WithScope(context.Background(), "colegio-x")

	data, err := svc.GetByID(ctx, 1)
	assert.NoError(t, err)
	assert.Equal(t, "12345678-5", data.Rut)
	assert.Equal(t, "Juan Pérez", data.Nombre)
	assert.Equal(t, "8°B", data.Curso)
}
