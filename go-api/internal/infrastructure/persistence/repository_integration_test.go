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

	// Verificar que Docker esté disponible antes de intentar levantar el contenedor.
	// Si no hay Docker, el test hace skip (no falla) — esto permite correr
	// la suite completa sin Docker sin que explote.
	dockerClient, err := testcontainers.NewDockerClientWithOpts(ctx)
	if err != nil {
		t.Skipf("Docker no disponible, saltando test de integración: %v", err)
	}
	defer dockerClient.Close()

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

	// 3. Conectar sin migraciones (ConnectPostgres no busca el directorio migrations/)
	db, err := persistence.ConnectPostgres(connStr)
	require.NoError(t, err)

	// Crear schema mínimo para los tests (tablas necesarias para el repositorio)
	err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id bigserial PRIMARY KEY, created_at timestamptz, updated_at timestamptz, deleted_at timestamptz,
			username text NOT NULL UNIQUE, password text NOT NULL,
			email_encrypted text NOT NULL DEFAULT '', email_hash text NOT NULL DEFAULT '',
			failed_attempts int NOT NULL DEFAULT 0, locked_until timestamptz, token_version int NOT NULL DEFAULT 1
		);
		CREATE TABLE IF NOT EXISTS roles (
			id bigserial PRIMARY KEY, created_at timestamptz, updated_at timestamptz, deleted_at timestamptz,
			name text NOT NULL UNIQUE
		);
		CREATE TABLE IF NOT EXISTS permissions (
			id bigserial PRIMARY KEY, created_at timestamptz, updated_at timestamptz, deleted_at timestamptz,
			name text NOT NULL UNIQUE
		);
		CREATE TABLE IF NOT EXISTS user_roles (
			user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			role_id bigint NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
			PRIMARY KEY (user_id, role_id)
		);
		CREATE TABLE IF NOT EXISTS role_permissions (
			role_id bigint NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
			permission_id bigint NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
			PRIMARY KEY (role_id, permission_id)
		)
	`).Error
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

func TestRoleRepository_Integration_SoftDeleteUniqueIndex(t *testing.T) {
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
			wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		t.Skipf("No se pudo levantar PostgreSQL en Docker: %v", err)
	}
	defer func() { _ = pgContainer.Terminate(ctx) }()

	host, err := pgContainer.Host(ctx)
	require.NoError(t, err)
	port, err := pgContainer.MappedPort(ctx, "5432")
	require.NoError(t, err)

	dsn := "postgresql://testuser:testpass@" + host + ":" + port.Port() + "/testdb?sslmode=disable"

	// Usar AutoMigrate para crear schema sin depender de carpeta migrations
	db, err := persistence.ConnectPostgres(dsn)
	require.NoError(t, err)

	err = db.AutoMigrate(
		&persistence.User{},
		&persistence.Role{},
		&persistence.Permission{},
		&persistence.RefreshToken{},
		&persistence.AuditLog{},
	)
	require.NoError(t, err)

	// Crear índices parciales (el fix del bug)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	defer sqlDB.Close()

	_, _ = sqlDB.Exec("DROP INDEX IF EXISTS idx_roles_name")
	_, err = sqlDB.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_roles_name_active ON roles (name) WHERE deleted_at IS NULL")
	require.NoError(t, err)

	_, _ = sqlDB.Exec("DROP INDEX IF EXISTS idx_permissions_name")
	_, err = sqlDB.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_permissions_name_active ON permissions (name) WHERE deleted_at IS NULL")
	require.NoError(t, err)

	repo := persistence.NewRoleRepository(db)

	// Test: Crear rol, soft-delete, y recrear con el mismo nombre debe funcionar.
	t.Run("Soft delete permite recrear rol con mismo nombre", func(t *testing.T) {
		roleName := "test-editor-role"

		// 1. Crear rol
		role := &domain.Role{Name: roleName}
		err := repo.Create(ctx, role)
		require.NoError(t, err, "crear rol debe funcionar")
		assert.NotZero(t, role.ID)

		// 2. Soft delete
		err = repo.Delete(ctx, role.ID)
		require.NoError(t, err, "soft delete debe funcionar")

		// 3. Recrear con mismo nombre — esto fallaba antes del fix de índice parcial
		role2 := &domain.Role{Name: roleName}
		err = repo.Create(ctx, role2)
		require.NoError(t, err, "recrear rol después de soft delete debe funcionar")
		assert.NotZero(t, role2.ID)
		assert.NotEqual(t, role.ID, role2.ID, "debe ser un rol nuevo con ID diferente")
	})
}
