-- Tabla de estudiantes (solo dato, nunca usuario).
-- PII cifrada a nivel de aplicacion: rut_encrypted/nombre_encrypted (AES-256-GCM),
-- rut_hash (HMAC-SHA256) como indice unico para busqueda/unicidad sin exponer el RUT.

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
CREATE INDEX IF NOT EXISTS idx_estudiantes_curso ON estudiantes (curso);
CREATE INDEX IF NOT EXISTS idx_estudiantes_scope ON estudiantes (scope);
CREATE INDEX IF NOT EXISTS idx_estudiantes_deleted_at ON estudiantes (deleted_at);
