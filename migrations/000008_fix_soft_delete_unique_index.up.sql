-- Fix: Soft Delete + Unique Index conflict.
--
-- Problema: GORM uniqueIndex aplica a TODOS los registros, incluyendo soft-deleted.
-- Esto impide crear un nuevo rol/permiso con el mismo nombre de uno borrado.
--
-- Solución: Reemplazar índices únicos globales con índices parciales que solo
-- apliquen a registros activos (deleted_at IS NULL).

-- Roles
DROP INDEX IF EXISTS idx_roles_name;
CREATE UNIQUE INDEX IF NOT EXISTS idx_roles_name_active ON roles (name) WHERE deleted_at IS NULL;

-- Permissions
DROP INDEX IF EXISTS idx_permissions_name;
CREATE UNIQUE INDEX IF NOT EXISTS idx_permissions_name_active ON permissions (name) WHERE deleted_at IS NULL;

-- Users (username también puede tener este problema con soft delete)
DROP INDEX IF EXISTS idx_users_username;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_active ON users (username) WHERE deleted_at IS NULL;
