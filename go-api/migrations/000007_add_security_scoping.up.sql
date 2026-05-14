-- Agrega campos de seguridad avanzada para scoping y protección de roles críticos.
--
-- is_system: true para roles que NO pueden ser eliminados (Admin, User).
-- scope: restringe visibilidad de roles y usuarios a administradores de ese dominio.
--        Scope vacío ('') significa acceso global.

ALTER TABLE roles
    ADD COLUMN IF NOT EXISTS is_system boolean NOT NULL DEFAULT false;

ALTER TABLE roles
    ADD COLUMN IF NOT EXISTS scope varchar(100) NOT NULL DEFAULT '';

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS scope varchar(100) NOT NULL DEFAULT '';

-- Índice compuesto para consultas frecuentes de scoping.
CREATE INDEX IF NOT EXISTS idx_roles_scope_name ON roles (scope, name);
CREATE INDEX IF NOT EXISTS idx_users_scope ON users (scope);
