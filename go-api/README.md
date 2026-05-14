# Go API Server — Clean Architecture RBAC Enterprise

API REST de alta disponibilidad construida en Go con **Clean Architecture**, **RBAC dinámico enterprise**, **auditoría forense**, y **scoping administrativo**.

## Características Principales

### Arquitectura
- **Clean Architecture / Hexagonal**: Separación estricta Domain → Application → Infrastructure → Presentation
- **Domain-Driven Design**: Entidades puras con invariantes protegidas (factory `NewUser`, account lockout)
- **Inyección de Dependencias**: 100% testable, mocks generados con mockery
- **Fat JWT (O(1) Auth)**: Permisos embebidos en token, cero consultas N+1 a DB por request

### Seguridad Enterprise
- **RBAC Dinámico**: Roles y permisos gestionables vía API sin redeploy
- **Protección de Roles Críticos**: `Admin` y `User` marcados como `IsSystem` — no se pueden eliminar ni renombrar
- **Scoping Administrativo**: Multi-tenant por dominio. Un admin de "equipo-a" solo ve/modifica recursos de su scope
- **Auditoría Forense**: Tabla `audit_logs` registra quién, qué, cuándo, old/new values en JSON
- **Account Lockout**: Bloqueo progresivo tras `MaxFailedAttempts` intentos fallidos
- **PII Protection**: Emails cifrados con AES-256-GCM, buscables por HMAC-SHA256 determinista
- **Rate Limiting**: 1 req/s con ráfagas de 5 en rutas de autenticación (protección bcrypt)
- **Token Version Cache**: Cache en memoria con TTL 30s para validar `token_version` sin hits a DB
- **Refresh Token Rotation**: Tokens de uso único, previenen replay attacks

### Operaciones Administrativas
- **Paginación**: Todos los listados soportan `?page=` y `?size=` (máx 100)
- **Búsqueda**: `GET /users?search=john&role=Admin` — case-insensitive
- **Soft Delete + Restore**: Items borrados se pueden recuperar (`POST /.../{id}/restore`)
- **Bulk Operations**: `POST /users/bulk/roles` asigna roles a múltiples usuarios atómicamente
- **Metadata**: Roles y permisos tienen campo `description` para documentación

---

## Estructura del Proyecto

```text
cmd/api/main.go                          # Entrypoint: DI wiring + graceful shutdown

internal/
  config/                                # Variables de entorno (fail-fast en startup)
  domain/                                # Entidades puras, interfaces (puertos), errores
    user.go                              # User, NewUser, Account Lockout, HasPermission
    role.go                              # Role, Permission, IsSystem, Scope
    user_repo.go                         # UserRepository (UserReader + UserWriter + TokenStore)
    role_repo.go                         # RoleRepository
    audit_repo.go                        # AuditRepository
    errors.go                            # Errores de dominio (ErrRoleImmutable, ErrScopeMismatch, ...)
  application/                           # Casos de uso, lógica de negocio orquestada
    auth_service.go                      # Register, Login, Refresh, Logout
    user_service.go                      # CRUD usuarios, SearchUsers, BulkAssignRolesToUsers
    role_service.go                      # CRUD roles/permisos, SearchRoles, RestoreRole
    audit_context.go                     # WithActor, ActorFromContext, WithScope, ScopeFromContext
    audit_helper.go                      # auditService.log + canAccessScope/assertScopeAccess
    audit_test.go                        # Tests de auditoría
    *_test.go                            # Tests unitarios de servicios
  infrastructure/
    persistence/
      postgres.go                        # Conexión GORM + golang-migrate + seedDefaults
      gorm_models.go                     # User, Role, Permission, RefreshToken, AuditLog
      user_repository.go                 # Implementación UserRepository
      role_repository.go                 # Implementación RoleRepository
      audit_repository.go                # Implementación AuditRepository
    cache/token_version_cache.go         # sync.Map con TTL 30s
    crypto/encryptor.go                  # AES-256-GCM + HMAC-SHA256
  presentation/rest/
    router.go                            # Registro de rutas + middlewares
    handlers/                            # DTOs + handlers HTTP
      auth_handler.go
      user_handler.go
      role_handler.go
      health_handler.go
      response.go                        # RespondJSON, RespondError, DecodeAndValidate, withActor
    middleware/
      auth.go                            # RequireAuth (JWT + token_version), RequirePermission
      rate_limiter.go
      cors.go
      request_logger.go

migrations/                              # 7 migraciones versionadas (golang-migrate)
  000001_create_schema                   # Tablas base: users, roles, permissions, pivotes
  000002_create_refresh_tokens           # refresh_tokens con índice único
  000003_add_security_fields             # email_encrypted, email_hash, failed_attempts, locked_until
  000004_add_token_version               # token_version para invalidación de JWT
  000005_create_audit_logs               # Auditoría forense: action, actor, target, old/new values
  000006_add_description_fields          # description en roles y permisos
  000007_add_security_scoping            # is_system, scope en roles y usuarios

mocks/                                   # Generados por mockery (go generate ./...)
docs/                                    # Swagger/OpenAPI generado por swaggo
```

---

## Configuración

| Variable | Requerida | Descripción |
|---|---|---|
| `JWT_SECRET` | ✅ | Clave HMAC para firmar JWTs (mínimo 64 caracteres) |
| `DB_DSN` | ✅ | DSN PostgreSQL para GORM |
| `MIGRATION_DSN` | ✅ | DSN para golang-migrate (puede ser igual a DB_DSN) |
| `EMAIL_ENCRYPTION_KEY` | ✅ | Clave AES-256 (exactamente 32 bytes) |
| `PORT` | ➖ | Default: `8080` |
| `APP_ENV` | ➖ | Default: `development` |

La app hace **fail-fast** en startup si falta alguna variable requerida.

---

## Ejecución

```bash
# Local
go mod tidy
go run cmd/api/main.go

# Docker
docker compose up -d --build
```

> Nota: Tras agregar nuevas migraciones, el contenedor necesita `docker compose up -d --build` para aplicarlas.

---

## Endpoints

### Autenticación (sin token)

| Método | Ruta | Descripción |
|---|---|---|
| POST | `/api/v1/register` | Registro. Body: `{"username","password","email"}` |
| POST | `/api/v1/login` | Login. Retorna `access_token` + `refresh_token` |
| POST | `/api/v1/refresh` | Rota refresh token, emite nuevos tokens |
| POST | `/api/v1/logout` | Invalida todos los refresh tokens del usuario |

### Usuarios (requiere JWT)

| Método | Ruta | Permiso | Descripción |
|---|---|---|---|
| GET | `/api/v1/me` | — | Perfil del usuario autenticado |
| GET | `/api/v1/users` | `read:users` | Listar paginado. Query: `?page=&size=&search=&role=` |
| GET | `/api/v1/users/deleted` | `manage:users` | Listar usuarios soft-deleted |
| GET | `/api/v1/users/{id}` | `read:users` | Detalle de usuario |
| POST | `/api/v1/users` | `manage:users` | Crear usuario |
| PUT | `/api/v1/users/{id}` | `manage:users` | Actualizar usuario |
| DELETE | `/api/v1/users/{id}` | `manage:users` | Soft-delete usuario |
| POST | `/api/v1/users/{id}/restore` | `manage:users` | Restaurar usuario soft-deleted |
| PUT | `/api/v1/users/{id}/roles` | `manage:roles` | Asignar roles a usuario |
| POST | `/api/v1/users/bulk/roles` | `manage:roles` | Asignar roles a múltiples usuarios |

### Roles y Permisos (requiere `manage:roles`)

| Método | Ruta | Descripción |
|---|---|---|
| GET | `/api/v1/roles` | Listar roles. Query: `?page=&size=&search=` |
| GET | `/api/v1/roles/deleted` | Listar roles soft-deleted |
| POST | `/api/v1/roles` | Crear rol. Body: `{"name","description"}` |
| GET | `/api/v1/roles/{id}` | Detalle de rol |
| PUT | `/api/v1/roles/{id}` | Actualizar rol. System roles: solo descripción editable |
| DELETE | `/api/v1/roles/{id}` | Soft-delete rol. **Rechazado si IsSystem=true** |
| POST | `/api/v1/roles/{id}/restore` | Restaurar rol soft-deleted |
| PUT | `/api/v1/roles/{id}/permissions` | Asignar permisos a rol |
| GET | `/api/v1/permissions` | Listar permisos. Query: `?page=&size=` |
| POST | `/api/v1/permissions` | Crear permiso. Body: `{"name","description"}` |

### Healthchecks

| Método | Ruta | Descripción |
|---|---|---|
| GET | `/health/liveness` | Kubernetes liveness probe |
| GET | `/health/readiness` | Verifica conexión a PostgreSQL |

### Documentación

Swagger UI: `/swagger/index.html` (cuando la API está corriendo)

---

## Testing

```bash
# Todos los tests
go test ./...

# Con race detector
make test

# Cobertura HTML
make test-cov

# Regenerar mocks (tras modificar interfaces)
make generate

# Regenerar Swagger
make swag
```

Los mocks en `mocks/` son generados automáticamente por [mockery](https://github.com/vektra/mockery). No editar manualmente.

---

## Seguridad: Scoping Administrativo

El campo `scope` en usuarios y roles permite aislamiento multi-tenant:

- **Super-admin**: Usuario con `scope = ""` (vacío). Accede a TODO.
- **Admin de equipo**: Usuario con `scope = "equipo-a"`. Solo ve/modifica:
  - Usuarios con `scope = "equipo-a"` o `scope = ""`
  - Roles con `scope = "equipo-a"` o `scope = ""`
- **Roles system**: `Admin` y `User` tienen `IsSystem = true`. No se pueden eliminar ni renombrar (cualquier scope).

El scope del usuario autenticado se embebe en el JWT como claim `"scope"` y se valida en cada operación de escritura.

---

## Auditoría

Todas las operaciones mutantes (crear, actualizar, eliminar, asignar, restaurar) registran un log en `audit_logs`:

| Campo | Descripción |
|---|---|
| `action` | Tipo de operación: `create_role`, `update_user`, `delete_role`, `assign_permissions`, `restore_user`, etc. |
| `actor_id` | ID del usuario que ejecutó la acción |
| `target_type` | Tipo de recurso: `role`, `user`, `permission` |
| `target_id` | ID del recurso afectado |
| `old_value` / `new_value` | JSON con estado anterior y posterior |
| `created_at` | Timestamp de la operación |

Los logs son persistidos automáticamente y no interrumpen la operación principal (fail-safe).
