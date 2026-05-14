-- Agrega campos de descripción legible para roles y permisos.
-- Estos campos son opcionales y sirven para documentar el propósito
-- de cada rol/permiso en el panel de administración.
ALTER TABLE roles
    ADD COLUMN IF NOT EXISTS description text;

ALTER TABLE permissions
    ADD COLUMN IF NOT EXISTS description text;
