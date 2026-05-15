-- Revertir índices parciales a únicos globales (no recomendado en producción)
DROP INDEX IF EXISTS idx_roles_name_active;
DROP INDEX IF EXISTS idx_permissions_name_active;
DROP INDEX IF EXISTS idx_users_username_active;

CREATE UNIQUE INDEX IF NOT EXISTS idx_roles_name ON roles (name);
CREATE UNIQUE INDEX IF NOT EXISTS idx_permissions_name ON permissions (name);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users (username);
