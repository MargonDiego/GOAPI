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

func TestRoleRepository_Integration_ScopingAndRestore(t *testing.T) {
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

	db, err := persistence.ConnectPostgres(dsn)
	require.NoError(t, err)

	err = db.AutoMigrate(&persistence.User{}, &persistence.Role{}, &persistence.Permission{}, &persistence.RefreshToken{}, &persistence.AuditLog{})
	require.NoError(t, err)

	roleRepo := persistence.NewRoleRepository(db)
	userRepo := persistence.NewUserRepository(db)

	t.Run("Role scoping isolates roles by scope", func(t *testing.T) {
		// Crear roles con diferentes scopes
		globalRole := &domain.Role{Name: "global-admin", Scope: ""}
		err := roleRepo.Create(ctx, globalRole)
		require.NoError(t, err)

		scopedRole := &domain.Role{Name: "tenant-admin", Scope: "tenant-a"}
		err = roleRepo.Create(ctx, scopedRole)
		require.NoError(t, err)

		// Listar roles sin scope debe retornar ambos (global + scope vacío)
		all, err := roleRepo.FindAll(ctx)
		require.NoError(t, err)
		assert.Len(t, all, 2, "FindAll debe retornar todos los roles")

		// Listar roles con scope "tenant-a" debe retornar global + tenant-a
		scoped, err := roleRepo.FindAllByScope(ctx, "tenant-a")
		require.NoError(t, err)
		assert.Len(t, scoped, 2, "FindAllByScope debe retornar roles del scope + globales")

		// Listar roles con scope diferente solo debe retornar global
		otherScoped, err := roleRepo.FindAllByScope(ctx, "tenant-b")
		require.NoError(t, err)
		assert.Len(t, otherScoped, 1, "FindAllByScope para otro scope solo debe retornar globales")
		assert.Equal(t, "global-admin", otherScoped[0].Name)
	})

	t.Run("Role restore recovers soft-deleted role", func(t *testing.T) {
		role := &domain.Role{Name: "restorable-role"}
		err := roleRepo.Create(ctx, role)
		require.NoError(t, err)
		require.NotZero(t, role.ID)

		// Soft delete
		err = roleRepo.Delete(ctx, role.ID)
		require.NoError(t, err)

		// Verificar que no aparece en listados normales
		_, err = roleRepo.FindByID(ctx, role.ID)
		assert.ErrorIs(t, err, domain.ErrRoleNotFound, "rol soft-deleted no debe encontrarse por ID")

		// Verificar que aparece en listado de eliminados
		deleted, err := roleRepo.FindAllDeleted(ctx)
		require.NoError(t, err)
		assert.Len(t, deleted, 1, "debe haber exactamente un rol eliminado")
		assert.Equal(t, "restorable-role", deleted[0].Name)

		// Restaurar
		err = roleRepo.Restore(ctx, role.ID)
		require.NoError(t, err, "restore debe funcionar")

		// Verificar que vuelve a aparecer
		restored, err := roleRepo.FindByID(ctx, role.ID)
		require.NoError(t, err)
		assert.Equal(t, "restorable-role", restored.Name)

		// Verificar que ya no está en eliminados
		deletedAfter, err := roleRepo.FindAllDeleted(ctx)
		require.NoError(t, err)
		assert.Len(t, deletedAfter, 0, "no debe quedar ningún rol eliminado")
	})

	t.Run("User scoping isolates users by scope", func(t *testing.T) {
		// Crear usuarios con diferentes scopes y emails únicos
		globalUser := &domain.User{Username: "global-user", PasswordHash: "hash", EmailHash: "global@example.com", Scope: ""}
		err := userRepo.Create(ctx, globalUser)
		require.NoError(t, err)

		scopedUser := &domain.User{Username: "tenant-user", PasswordHash: "hash", EmailHash: "tenant@example.com", Scope: "tenant-a"}
		err = userRepo.Create(ctx, scopedUser)
		require.NoError(t, err)

		// Listar usuarios con scope "tenant-a" debe retornar global + tenant-a
		scoped, err := userRepo.FindAllByScope(ctx, "tenant-a", 1, 10)
		require.NoError(t, err)
		assert.Len(t, scoped, 2, "FindAllByScope debe retornar usuarios del scope + globales")

		// Listar usuarios con scope diferente solo debe retornar global
		otherScoped, err := userRepo.FindAllByScope(ctx, "tenant-b", 1, 10)
		require.NoError(t, err)
		assert.Len(t, otherScoped, 1, "FindAllByScope para otro scope solo debe retornar globales")
		assert.Equal(t, "global-user", otherScoped[0].Username)
	})

	t.Run("User restore recovers soft-deleted user", func(t *testing.T) {
		user := &domain.User{Username: "restorable-user", PasswordHash: "hash", EmailHash: "restore@example.com"}
		err := userRepo.Create(ctx, user)
		require.NoError(t, err)
		require.NotZero(t, user.ID)

		// Soft delete
		err = userRepo.Delete(ctx, user.ID)
		require.NoError(t, err)

		// Verificar que no aparece en listados normales
		_, err = userRepo.FindByID(ctx, user.ID)
		assert.ErrorIs(t, err, domain.ErrUserNotFound, "usuario soft-deleted no debe encontrarse por ID")

		// Verificar que aparece en listado de eliminados
		deleted, err := userRepo.FindAllDeleted(ctx)
		require.NoError(t, err)
		assert.Len(t, deleted, 1, "debe haber exactamente un usuario eliminado")
		assert.Equal(t, "restorable-user", deleted[0].Username)

		// Restaurar
		err = userRepo.Restore(ctx, user.ID)
		require.NoError(t, err, "restore debe funcionar")

		// Verificar que vuelve a aparecer
		restored, err := userRepo.FindByID(ctx, user.ID)
		require.NoError(t, err)
		assert.Equal(t, "restorable-user", restored.Username)

		// Verificar que ya no está en eliminados
		deletedAfter, err := userRepo.FindAllDeleted(ctx)
		require.NoError(t, err)
		assert.Len(t, deletedAfter, 0, "no debe quedar ningún usuario eliminado")
	})
}
