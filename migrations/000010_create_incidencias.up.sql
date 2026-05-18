CREATE TABLE IF NOT EXISTS incidencias (
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

-- Código único por scope (excluye borrados)
CREATE UNIQUE INDEX IF NOT EXISTS idx_incidencias_codigo_scope
    ON incidencias (codigo, scope)
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_incidencias_estado       ON incidencias (estado);
CREATE INDEX IF NOT EXISTS idx_incidencias_scope        ON incidencias (scope);
CREATE INDEX IF NOT EXISTS idx_incidencias_estudiante   ON incidencias (estudiante_id);
CREATE INDEX IF NOT EXISTS idx_incidencias_responsable  ON incidencias (responsable_id) WHERE responsable_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_incidencias_deleted_at   ON incidencias (deleted_at);
