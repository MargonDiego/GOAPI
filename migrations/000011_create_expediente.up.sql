-- Comentarios (append-only, hilo de trabajo)
CREATE TABLE IF NOT EXISTS comentarios (
    id            bigserial    PRIMARY KEY,
    incidencia_id bigint       NOT NULL REFERENCES incidencias(id),
    autor_id      bigint       NOT NULL,
    cuerpo        text         NOT NULL,
    created_at    timestamptz  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_comentarios_incidencia ON comentarios (incidencia_id);

-- Adjuntos (metadata; archivo físico en disco)
CREATE TABLE IF NOT EXISTS adjuntos (
    id                bigserial    PRIMARY KEY,
    incidencia_id     bigint       NOT NULL REFERENCES incidencias(id),
    nombre_original   varchar(255) NOT NULL,
    nombre_almacenado varchar(255) NOT NULL,
    mime_type         varchar(100) NOT NULL DEFAULT '',
    tamano_bytes      bigint       NOT NULL DEFAULT 0,
    hash_sha256       varchar(64)  NOT NULL DEFAULT '',
    subido_por_id     bigint       NOT NULL,
    created_at        timestamptz  NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_adjuntos_nombre_almacenado UNIQUE (nombre_almacenado)
);
CREATE INDEX IF NOT EXISTS idx_adjuntos_incidencia ON adjuntos (incidencia_id);

-- Medidas (formativas o disciplinarias)
CREATE TABLE IF NOT EXISTS medidas (
    id                       bigserial    PRIMARY KEY,
    incidencia_id            bigint       NOT NULL REFERENCES incidencias(id),
    clase                    varchar(20)  NOT NULL,
    tipo                     varchar(30)  NOT NULL,
    descripcion              text         NOT NULL DEFAULT '',
    proporcionalidad         text         NOT NULL DEFAULT '',
    responsable_ejecucion_id bigint       NOT NULL,
    fecha_inicio             timestamptz,
    fecha_termino            timestamptz,
    estado_cumplimiento      varchar(20)  NOT NULL DEFAULT 'PENDIENTE',
    created_at               timestamptz  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_medidas_incidencia ON medidas (incidencia_id);

-- Descargos (derecho a ser oído — debido proceso)
CREATE TABLE IF NOT EXISTS descargos (
    id                  bigserial    PRIMARY KEY,
    incidencia_id       bigint       NOT NULL REFERENCES incidencias(id),
    presentado_por_id   bigint       NOT NULL,
    contenido           text         NOT NULL DEFAULT '',
    fecha_presentacion  timestamptz  NOT NULL DEFAULT NOW(),
    created_at          timestamptz  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_descargos_incidencia ON descargos (incidencia_id);

-- Resoluciones (decisión motivada — obligatoria por Ley 20.536)
CREATE TABLE IF NOT EXISTS resoluciones (
    id               bigserial    PRIMARY KEY,
    incidencia_id    bigint       NOT NULL REFERENCES incidencias(id),
    tipo             varchar(20)  NOT NULL DEFAULT 'ORIGINAL',
    fundamentacion   text         NOT NULL DEFAULT '',
    decision         text         NOT NULL DEFAULT '',
    resuelto_por_id  bigint       NOT NULL,
    fecha_resolucion timestamptz  NOT NULL DEFAULT NOW(),
    created_at       timestamptz  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_resoluciones_incidencia ON resoluciones (incidencia_id);

-- Apelaciones
CREATE TABLE IF NOT EXISTS apelaciones (
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
CREATE INDEX IF NOT EXISTS idx_apelaciones_incidencia ON apelaciones (incidencia_id);

-- Notificaciones al apoderado con control de acuse (debido proceso)
CREATE TABLE IF NOT EXISTS notificaciones (
    id                  bigserial    PRIMARY KEY,
    incidencia_id       bigint       NOT NULL REFERENCES incidencias(id),
    destinatario        varchar(255) NOT NULL DEFAULT '',
    medio               varchar(50)  NOT NULL DEFAULT '',
    contenido           text         NOT NULL DEFAULT '',
    fecha_notificacion  timestamptz  NOT NULL DEFAULT NOW(),
    acuse               boolean      NOT NULL DEFAULT false,
    fecha_acuse         timestamptz,
    created_at          timestamptz  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_notificaciones_incidencia ON notificaciones (incidencia_id);

-- Historial legal inmutable (expediente — SIN IP/UA para retención diferenciada Ley 21.719)
CREATE TABLE IF NOT EXISTS incidencia_eventos (
    id               bigserial    PRIMARY KEY,
    incidencia_id    bigint       NOT NULL REFERENCES incidencias(id),
    tipo             varchar(30)  NOT NULL,
    actor_id         bigint       NOT NULL,
    resumen          text         NOT NULL DEFAULT '',
    estado_anterior  varchar(30),
    estado_nuevo     varchar(30),
    created_at       timestamptz  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_eventos_incidencia ON incidencia_eventos (incidencia_id);
