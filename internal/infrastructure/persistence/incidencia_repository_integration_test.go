//go:build integration

package persistence_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/MargonDiego/GOAPI/internal/domain"
	"github.com/MargonDiego/GOAPI/internal/infrastructure/persistence"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	gormpostgres "gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func setupIncidenciaDB(t *testing.T) *gorm.DB {
	t.Helper()
	ctx := context.Background()

	pgc, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		tc.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(30*time.Second)),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pgc.Terminate(ctx) })

	dsn, err := pgc.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	db, err := gorm.Open(gormpostgres.Open(dsn), &gorm.Config{})
	require.NoError(t, err)

	// Crear schema mínimo para el test
	require.NoError(t, db.Exec(`
		CREATE TABLE incidencias (
			id                           bigserial PRIMARY KEY,
			codigo                       varchar(20)  NOT NULL,
			estudiante_id                bigint       NOT NULL,
			titulo                       varchar(200) NOT NULL,
			descripcion                  text         NOT NULL DEFAULT '',
			gravedad                     varchar(20)  NOT NULL,
			categoria                    varchar(50)  NOT NULL,
			es_constitutivo_de_delito    boolean      NOT NULL DEFAULT false,
			estado                       varchar(30)  NOT NULL DEFAULT 'RECIBIDA',
			denunciante_id               bigint       NOT NULL,
			responsable_id               bigint,
			scope                        varchar(100) NOT NULL DEFAULT '',
			suspension_preventiva        boolean      NOT NULL DEFAULT false,
			fecha_suspension_preventiva  timestamptz,
			fecha_recepcion              timestamptz  NOT NULL DEFAULT NOW(),
			fecha_inicio_investigacion   timestamptz,
			fecha_cierre                 timestamptz,
			fecha_eliminacion_programada timestamptz,
			created_at                   timestamptz  NOT NULL DEFAULT NOW(),
			updated_at                   timestamptz  NOT NULL DEFAULT NOW(),
			deleted_at                   timestamptz
		);
		CREATE TABLE comentarios (
			id bigserial PRIMARY KEY,
			incidencia_id bigint NOT NULL REFERENCES incidencias(id),
			autor_id      bigint NOT NULL,
			cuerpo        text   NOT NULL,
			created_at    timestamptz NOT NULL DEFAULT NOW()
		);
		CREATE TABLE adjuntos (
			id                bigserial    PRIMARY KEY,
			incidencia_id     bigint       NOT NULL REFERENCES incidencias(id),
			nombre_original   varchar(255) NOT NULL,
			nombre_almacenado varchar(255) NOT NULL UNIQUE,
			mime_type         varchar(100) NOT NULL DEFAULT '',
			tamano_bytes      bigint       NOT NULL DEFAULT 0,
			hash_sha256       varchar(64)  NOT NULL DEFAULT '',
			subido_por_id     bigint       NOT NULL,
			created_at        timestamptz  NOT NULL DEFAULT NOW()
		);
		CREATE TABLE resoluciones (
			id               bigserial    PRIMARY KEY,
			incidencia_id    bigint       NOT NULL REFERENCES incidencias(id),
			tipo             varchar(20)  NOT NULL DEFAULT 'ORIGINAL',
			fundamentacion   text         NOT NULL DEFAULT '',
			decision         text         NOT NULL DEFAULT '',
			resuelto_por_id  bigint       NOT NULL,
			fecha_resolucion timestamptz  NOT NULL DEFAULT NOW(),
			created_at       timestamptz  NOT NULL DEFAULT NOW()
		);
		CREATE TABLE apelaciones (
			id                  bigserial    PRIMARY KEY,
			incidencia_id       bigint       NOT NULL REFERENCES incidencias(id),
			resolucion_id       bigint       NOT NULL REFERENCES resoluciones(id),
			presentada_por_id   bigint       NOT NULL,
			motivo              text         NOT NULL DEFAULT '',
			fecha_presentacion  timestamptz  NOT NULL DEFAULT NOW(),
			plazo_vencimiento   timestamptz  NOT NULL,
			estado              varchar(20)  NOT NULL DEFAULT 'PENDIENTE',
			created_at          timestamptz  NOT NULL DEFAULT NOW()
		);
		CREATE TABLE incidencia_eventos (
			id               bigserial    PRIMARY KEY,
			incidencia_id    bigint       NOT NULL REFERENCES incidencias(id),
			tipo             varchar(30)  NOT NULL,
			actor_id         bigint       NOT NULL,
			resumen          text         NOT NULL DEFAULT '',
			estado_anterior  varchar(30),
			estado_nuevo     varchar(30),
			created_at       timestamptz  NOT NULL DEFAULT NOW()
		);
	`).Error)

	return db
}

func newTestIncidencia(t *testing.T, scope string) *domain.Incidencia {
	t.Helper()
	inc, err := domain.NewIncidencia("Pelea en patio", "descripcion", domain.GravedadGrave, domain.CategoriaMaltratoEstudiantes, 1, 1, scope)
	require.NoError(t, err)
	inc.Codigo = fmt.Sprintf("INC-%d-0001", time.Now().Year())
	return inc
}

func TestIncidenciaRepository_CreateAndFindByID(t *testing.T) {
	db := setupIncidenciaDB(t)
	repo := persistence.NewIncidenciaRepository(db)
	ctx := context.Background()

	inc := newTestIncidencia(t, "colegio-a")
	require.NoError(t, repo.Create(ctx, inc))
	assert.NotZero(t, inc.ID)

	got, err := repo.FindByID(ctx, inc.ID)
	require.NoError(t, err)
	assert.Equal(t, inc.Codigo, got.Codigo)
	assert.Equal(t, domain.EstadoRecibida, got.Estado)
	assert.Equal(t, "colegio-a", got.Scope)
}

func TestIncidenciaRepository_FindByID_NotFound(t *testing.T) {
	db := setupIncidenciaDB(t)
	repo := persistence.NewIncidenciaRepository(db)

	_, err := repo.FindByID(context.Background(), 99999)
	assert.ErrorIs(t, err, domain.ErrIncidenciaNotFound)
}

func TestIncidenciaRepository_Update_Estado(t *testing.T) {
	db := setupIncidenciaDB(t)
	repo := persistence.NewIncidenciaRepository(db)
	ctx := context.Background()

	inc := newTestIncidencia(t, "colegio-b")
	require.NoError(t, repo.Create(ctx, inc))

	require.NoError(t, inc.IniciarInvestigacion(1, time.Now()))
	require.NoError(t, repo.Update(ctx, inc))

	got, err := repo.FindByID(ctx, inc.ID)
	require.NoError(t, err)
	assert.Equal(t, domain.EstadoEnInvestigacion, got.Estado)
	assert.NotNil(t, got.ResponsableID)
}

func TestIncidenciaRepository_AppendComentario(t *testing.T) {
	db := setupIncidenciaDB(t)
	repo := persistence.NewIncidenciaRepository(db)
	ctx := context.Background()

	inc := newTestIncidencia(t, "colegio-c")
	require.NoError(t, repo.Create(ctx, inc))

	c, err := domain.NewComentario(inc.ID, 1, "comentario de prueba")
	require.NoError(t, err)
	require.NoError(t, repo.AppendComentario(ctx, c))
	assert.NotZero(t, c.ID)

	lista, err := repo.ListComentarios(ctx, inc.ID)
	require.NoError(t, err)
	require.Len(t, lista, 1)
	assert.Equal(t, "comentario de prueba", lista[0].Cuerpo)
}

func TestIncidenciaRepository_CountByScope(t *testing.T) {
	db := setupIncidenciaDB(t)
	repo := persistence.NewIncidenciaRepository(db)
	ctx := context.Background()

	inc1 := newTestIncidencia(t, "colegio-x")
	inc1.Codigo = "INC-2026-0001"
	inc2 := newTestIncidencia(t, "colegio-x")
	inc2.Codigo = "INC-2026-0002"
	require.NoError(t, repo.Create(ctx, inc1))
	require.NoError(t, repo.Create(ctx, inc2))

	count, err := repo.CountByScope(ctx, "colegio-x", time.Now().Year())
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)
}

func TestIncidenciaRepository_Search(t *testing.T) {
	db := setupIncidenciaDB(t)
	repo := persistence.NewIncidenciaRepository(db)
	ctx := context.Background()

	inc := newTestIncidencia(t, "colegio-z")
	require.NoError(t, repo.Create(ctx, inc))

	results, total, err := repo.Search(ctx, domain.IncidenciaFilter{Scope: "colegio-z"}, 1, 10)
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Len(t, results, 1)

	// scope distinto no devuelve nada
	results2, total2, err := repo.Search(ctx, domain.IncidenciaFilter{Scope: "otro"}, 1, 10)
	require.NoError(t, err)
	assert.Equal(t, int64(0), total2)
	assert.Empty(t, results2)
}
