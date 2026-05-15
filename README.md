# Go API Server — Clean Architecture RBAC Enterprise

[![CI](https://github.com/MargonDiego/GOAPI/actions/workflows/ci.yml/badge.svg)](https://github.com/MargonDiego/GOAPI/actions/workflows/ci.yml)
![Go Version](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

API REST de alta disponibilidad construida en Go con **Clean Architecture**, **RBAC dinámico enterprise**, **auditoría forense**, y **scoping administrativo**.

## 🚀 Quickstart

```bash
# 1. Clonar y configurar
git clone https://github.com/MargonDiego/GOAPI.git && cd GOAPI
cp .env.example .env          # Editar .env con tus valores

# 2. Levantar con Docker (recomendado)
docker compose up -d --build

# 3. Probar
curl http://localhost:8080/health/liveness
#   → OK

curl -X POST http://localhost:8080/api/v1/register \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin1234","email":"admin@example.com"}'
#   → {"success":true,"data":{"message":"user registered successfully"}}
```

> **Swagger UI**: `http://localhost:8080/swagger/index.html`

### Sin Docker

```bash
# Requiere PostgreSQL corriendo en localhost:5432
go mod tidy
go run cmd/api/main.go
```

## Características Principales

### Arquitectura
- **Clean Architecture / Hexagonal**: Separación estricta Domain → Application → Infrastructure → Presentation
- **Domain-Driven Design**: Entidades puras con invariantes protegidas (factory `NewUser`, account lockout)
- **Inyección de Dependencias**: 100% testable, mocks generados con mockery
- **Fat JWT (O(1) Auth)**: Permisos embebidos en token, cero consultas N+1 a DB por request

### Seguridad Enterprise
- **RBAC Dinámico**: Roles y permisos gestionables vía API sin redeploy
- **Errores Tipados**: `AppError` con código HTTP + error code (`USER_NOT_FOUND`). Mapeo automático dominio→HTTP.
- **Protección de Roles Críticos**: `Admin` y `User` marcados como `IsSystem` — no se pueden eliminar ni renombrar
- **Scoping Administrativo**: Multi-tenant por dominio. Un admin de "equipo-a" solo ve/modifica recursos de su scope
- **Auditoría Forense**: Tabla `audit_logs` registra quién, qué, cuándo, old/new values en JSON
- **Account Lockout**: Bloqueo progresivo tras `MaxFailedAttempts` intentos fallidos
- **PII Protection**: Emails cifrados con AES-256-GCM, buscables por HMAC-SHA256 determinista
- **Rate Limiting**: 1 req/s con ráfagas de 5 en rutas de autenticación (protección bcrypt)
- **Token Version Cache**: Cache en memoria con TTL 30s para validar `token_version` sin hits a DB
- **Refresh Token Rotation**: Tokens de uso unico, previenen replay attacks
- **HttpOnly Cookies + CSRF**: Access token en cookie HttpOnly (inmune a XSS) con validacion de Origin en mutations

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
      response.go                        # APIResponse, MapDomainError, RenderError, DecodeAndValidate
      dto.go                             # ErrorResponse, MessageResponse
    middleware/
      auth.go                            # RequireAuth (JWT + token_version), RequirePermission
      panic_recovery.go                  # Captura panics → 500 + stack trace
      request_id.go                      # UUID por request (X-Request-ID)
      security_headers.go                # HSTS, CSP, X-Frame-Options, X-Content-Type
      cors.go                            # CORS configurable por origen
      rate_limiter.go                    # Token bucket por IP
      request_logger.go                  # Log estructurado con request_id

migrations/                              # 8 migraciones versionadas (golang-migrate)
  000001_create_schema                   # Tablas base: users, roles, permissions, pivotes
  000002_create_refresh_tokens           # refresh_tokens con índice único
  000003_add_security_fields             # email_encrypted, email_hash, failed_attempts, locked_until
  000004_add_token_version               # token_version para invalidación de JWT
   000005_create_audit_logs               # Auditoría forense: action, actor, target, old/new values
   000006_add_description_fields          # description en roles y permisos
   000007_add_security_scoping            # is_system, scope en roles y usuarios
   000008_fix_soft_delete_unique_index     # Índices parciales WHERE deleted_at IS NULL

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
| `APP_ENV` | ➖ | Default: `development`. En `production` activa HSTS. |
| `CORS_ORIGINS` | ➖ | Default: `http://localhost:3000`. Orígenes separados por coma. |

La app hace **fail-fast** en startup si falta alguna variable requerida.

---

## Formato de Respuesta

Todas las respuestas usan un envelope unificado:

```json
// Éxito (cualquier 2xx)
{
  "success": true,
  "data": { ... }
}

// Éxito paginado
{
  "success": true,
  "data": [ ... ],
  "meta": { "page": 1, "size": 10, "total": 42, "total_pages": 5 }
}

// Error de dominio (4xx) — incluye código legible por máquina
{
  "success": false,
  "error": "user not found",
  "code": "USER_NOT_FOUND"
}

// Error interno (5xx) — sin código para no exponer detalles
{
  "success": false,
  "error": "internal server error"
}

// Error de validación
{
  "success": false,
  "error": "validation failed",
  "data": ["username is required", "password must be at least 8 characters"]
}
```

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
| GET | `/api/v1/users` | `read:users` | Listar paginado. Query: `?page=&size=&search=&role=`. Respuesta: `{data, page, size, total, total_pages}` |
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
| GET | `/api/v1/roles` | Listar roles. Query: `?page=&size=&search=`. Respuesta: `{data, page, size, total, total_pages}` |
| GET | `/api/v1/roles/deleted` | Listar roles soft-deleted |
| POST | `/api/v1/roles` | Crear rol. Body: `{"name","description"}` |
| GET | `/api/v1/roles/{id}` | Detalle de rol |
| PUT | `/api/v1/roles/{id}` | Actualizar rol. System roles: solo descripción editable |
| DELETE | `/api/v1/roles/{id}` | Soft-delete rol. **Rechazado si IsSystem=true** |
| POST | `/api/v1/roles/{id}/restore` | Restaurar rol soft-deleted |
| PUT | `/api/v1/roles/{id}/permissions` | Asignar permisos a rol |
| GET | `/api/v1/permissions` | Listar permisos. Query: `?page=&size=`. Respuesta: `{data, page, size, total, total_pages}` |
| POST | `/api/v1/permissions` | Crear permiso. Body: `{"name","description"}` |

### Healthchecks

| Método | Ruta | Descripción |
|---|---|---|
| GET | `/` | Info de la API (nombre, versión, docs, health) |
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

# Tests de integración (requiere Docker)
go test -tags=integration ./internal/infrastructure/persistence/ -v -count=1

# Regenerar mocks (tras modificar interfaces)
make generate

# Regenerar Swagger
make swag
```

Los mocks en `mocks/` son generados automáticamente por [mockery](https://github.com/vektra/mockery). No editar manualmente.

---

---

## Middleware Stack

Los middlewares se ejecutan en orden — del más externo al más interno:

| # | Middleware | Propósito |
|---|-----------|-----------|
| 1 | `PanicRecovery` | Captura panics, loguea stack trace, retorna 500 |
| 2 | `RequestID` | UUID por request. Acepta `X-Request-ID` del cliente |
| 3 | `SecurityHeaders` | `X-Content-Type-Options`, `X-Frame-Options`, HSTS (prod), CSP |
| 4 | `CORS` | Orígenes configurables vía `CORS_ORIGINS` |
| 5 | `RequestLogger` | Log estructurado: metodo, path, status, duracion, request_id |
| 6 | `IPRateLimiter` | Token bucket por IP (10 req/s global, 1 req/s en auth) |
| 7 | `AuthMiddleware` | JWT via cookie HttpOnly (primario) o Bearer header (fallback) + validacion token_version + permisos en memoria |
| 8 | `CSRF` | Validacion de Origin/Referer en mutations (POST/PUT/DELETE) |

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
| `ip_address` | IP del cliente (X-Forwarded-For → X-Real-Ip → RemoteAddr) |
| `user_agent` | User-Agent del cliente |
| `created_at` | Timestamp de la operación |

Los logs son persistidos automáticamente y no interrumpen la operación principal (fail-safe).
