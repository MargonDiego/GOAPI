-- audit_logs registra cambios críticos en el sistema para trazabilidad forense y compliance.
-- Cada fila representa una acción realizada por un usuario (actor) sobre un recurso (target).
--
-- Scopes:
--   - action: tipo de operación (create_role, update_user, assign_permissions, etc.)
--   - actor_id: usuario que ejecutó la acción (referencia a users.id)
--   - target_type + target_id: recurso afectado (ej: role + 42)
--   - old_value / new_value: JSON con el estado antes y después
--   - ip_address / user_agent: contexto de la petición HTTP
CREATE TABLE IF NOT EXISTS audit_logs (
    id          bigserial PRIMARY KEY,
    action      varchar(100) NOT NULL,
    actor_id    bigint NOT NULL,
    target_type varchar(50) NOT NULL,
    target_id   bigint NOT NULL,
    old_value   text,
    new_value   text,
    ip_address  varchar(45),
    user_agent  varchar(255),
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- Índices para consultas forenses comunes.
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs (action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit_logs (actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_target ON audit_logs (target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs (created_at DESC);
