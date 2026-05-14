//go:build integration
// +build integration

// Package persistence_test contiene tests de integración que requieren Docker.
//
// Ejecutar con:
//
//	go test -tags=integration ./internal/infrastructure/persistence/ -v -count=1
//
// Requisitos: Docker corriendo en la máquina.
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

	"github.com/diego/go-api/internal/domain"
	"github.com/diego/go-api/internal/infrastructure/persistence"
)

func TestUserRepository_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("saltando test de integración en modo short")
	}

	ctx := context.Background()

	// 1. Levantar PostgreSQL en un contenedor Docker
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

	// 2. Obtener el DSN dinámico del contenedor
	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	// 3. Conectar usando la misma función de infraestructura (sin migraciones)
	db, err := persistence.NewPostgresDB(connStr, connStr)
	require.NoError(t, err)

	repo := persistence.NewUserRepository(db)

	// 4. Test: Crear usuario y luego buscarlo
	t.Run("Create y FindByUsername", func(t *testing.T) {
		user := &domain.User{
			Username:     "integration_test_user",
			PasswordHash: "$2a$10$dummyhash1234567890123456789012345678901234567890",
		}

		err := repo.Create(ctx, user)
		require.NoError(t, err)
		assert.NotZero(t, user.ID, "el repositorio debe propagar el ID generado")

		found, err := repo.FindByUsername(ctx, "integration_test_user")
		require.NoError(t, err)
		assert.Equal(t, user.ID, found.ID)
		assert.Equal(t, "integration_test_user", found.Username)
	})

	t.Run("FindByUsername no encontrado", func(t *testing.T) {
		_, err := repo.FindByUsername(ctx, "usuario_inexistente")
		assert.ErrorIs(t, err, domain.ErrUserNotFound)
	})
}
