-- Email cifrado con AES-256-GCM (ciphertext base64).
-- email_hash: HMAC-SHA256(email + secret_salt) para búsquedas sin descifrar.
-- DEFAULT '' solo para la migración — la aplicación siempre exige un email real.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS email_encrypted text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS email_hash      text NOT NULL DEFAULT '';

-- Índice único sobre el hash para búsquedas O(log n) sin exponer el email real.
-- WHERE email_hash != '' excluye filas vacías (datos previos sin email).
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_hash ON users (email_hash)
    WHERE email_hash != '';

-- Account Lockout: bloqueo progresivo por intentos fallidos.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS failed_attempts integer     NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS locked_until    timestamptz;
