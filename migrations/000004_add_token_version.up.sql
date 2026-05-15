-- token_version permite invalidar todos los JWT activos de un usuario en el momento
-- en que sus permisos cambian (rol asignado/removido, permiso modificado).
--
-- Flujo:
--   1. El JWT embebe token_version como claim "ver" al momento del login.
--   2. El middleware compara JWT.ver con users.token_version en cada request.
--   3. Si no coinciden → 401 Unauthorized (token stale, debe re-autenticarse).
--   4. AssignRolesToUser / AssignPermissionsToRole incrementan este campo.
--
-- DEFAULT 1 garantiza que los usuarios existentes tengan una versión válida.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS token_version integer NOT NULL DEFAULT 1;
