ALTER TABLE users
    DROP COLUMN IF EXISTS email_encrypted,
    DROP COLUMN IF EXISTS email_hash,
    DROP COLUMN IF EXISTS failed_attempts,
    DROP COLUMN IF EXISTS locked_until;
