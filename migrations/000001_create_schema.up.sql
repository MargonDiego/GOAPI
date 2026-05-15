-- Tabla de usuarios
CREATE TABLE IF NOT EXISTS users (
    id         bigserial PRIMARY KEY,
    created_at timestamptz,
    updated_at timestamptz,
    deleted_at timestamptz,
    username   text        NOT NULL,
    password   text        NOT NULL,
    CONSTRAINT users_username_key UNIQUE (username)
);
CREATE INDEX IF NOT EXISTS idx_users_deleted_at ON users (deleted_at);

-- Tabla de roles
CREATE TABLE IF NOT EXISTS roles (
    id         bigserial PRIMARY KEY,
    created_at timestamptz,
    updated_at timestamptz,
    deleted_at timestamptz,
    name       text        NOT NULL,
    CONSTRAINT roles_name_key UNIQUE (name)
);
CREATE INDEX IF NOT EXISTS idx_roles_deleted_at ON roles (deleted_at);

-- Tabla de permisos
CREATE TABLE IF NOT EXISTS permissions (
    id         bigserial PRIMARY KEY,
    created_at timestamptz,
    updated_at timestamptz,
    deleted_at timestamptz,
    name       text        NOT NULL,
    CONSTRAINT permissions_name_key UNIQUE (name)
);
CREATE INDEX IF NOT EXISTS idx_permissions_deleted_at ON permissions (deleted_at);

-- Tabla pivote: usuarios <-> roles
CREATE TABLE IF NOT EXISTS user_roles (
    user_id bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role_id bigint NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- Tabla pivote: roles <-> permisos
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id       bigint NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    permission_id bigint NOT NULL REFERENCES permissions (id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);
