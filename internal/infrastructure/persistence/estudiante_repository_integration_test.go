//go:build integration
// +build integration

package persistence_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/MargonDiego/GOAPI/internal/domain"
	"github.com/MargonDiego/GOAPI/internal/infrastructure/persistence"
)

func TestEstudianteRepository_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("saltando test de integración en modo short")
	}

	ctx := context.Background()

	dockerClient, err := testcontainers.NewDockerClientWithOpts(ctx)
	if err != nil {
		t.Skipf("Docker no disponible, saltando test de integración: %v", err)
	}
	defer dockerClient.Close()

	pgContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	require.NoError(t, err, "no se pudo levantar el contenedor PostgreSQL. ¿Docker está corriendo?")
	defer func() {
		if err := pgContainer.Terminate(ctx); err != nil {
			t.Logf("error al terminar contenedor: %v", err)
		}
	}()

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	db, err := persistence.ConnectPostgres(connStr)
	require.NoError(t, err)

	err = db.Exec(`
		CREATE TABLE IF NOT EXISTS estudiantes (
			id               BIGSERIAL PRIMARY KEY,
			created_at       TIMESTAMPTZ,
			updated_at       TIMESTAMPTZ,
			deleted_at       TIMESTAMPTZ,
			rut_hash         VARCHAR(64) NOT NULL,
			rut_encrypted    TEXT        NOT NULL,
			nombre_encrypted TEXT        NOT NULL,
			curso            VARCHAR(50) NOT NULL,
			scope            VARCHAR(100) NOT NULL DEFAULT ''
		);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_estudiantes_rut_hash
			ON estudiantes (rut_hash) WHERE deleted_at IS NULL;
		CREATE INDEX IF NOT EXISTS idx_estudiantes_deleted_at ON estudiantes (deleted_at);
	`).Error
	require.NoError(t, err)

	repo := persistence.NewEstudianteRepository(db)

	e := &domain.Estudiante{
		RutHash:         "hash-abc",
		RutEncrypted:    "enc-rut",
		NombreEncrypted: "enc-nombre",
		Curso:           "8°B",
		Scope:           "colegio-x",
	}

	t.Run("Create y FindByID", func(t *testing.T) {
		assert.NoError(t, repo.Create(ctx, e))
		assert.NotZero(t, e.ID)

		got, err := repo.FindByID(ctx, e.ID)
		assert.NoError(t, err)
		assert.Equal(t, "hash-abc", got.RutHash)
		assert.Equal(t, "8°B", got.Curso)
	})

	t.Run("FindByRutHash encontrado", func(t *testing.T) {
		byHash, err := repo.FindByRutHash(ctx, "hash-abc")
		assert.NoError(t, err)
		assert.Equal(t, e.ID, byHash.ID)
	})

	t.Run("FindByRutHash no encontrado", func(t *testing.T) {
		_, err := repo.FindByRutHash(ctx, "no-existe")
		assert.ErrorIs(t, err, domain.ErrEstudianteNotFound)
	})

	t.Run("Delete y FindByID retorna not found", func(t *testing.T) {
		assert.NoError(t, repo.Delete(ctx, e.ID))
		_, err := repo.FindByID(ctx, e.ID)
		assert.ErrorIs(t, err, domain.ErrEstudianteNotFound)
	})

	t.Run("Restore y FindByID ok", func(t *testing.T) {
		assert.NoError(t, repo.Restore(ctx, e.ID))
		_, err := repo.FindByID(ctx, e.ID)
		assert.NoError(t, err)
	})
}
