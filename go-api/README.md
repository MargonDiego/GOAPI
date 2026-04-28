# Go API Server - Clean Architecture (Production-Ready)

Este proyecto es una API REST escalable y de alto rendimiento construida en Go (Golang). Implementa principios de **Domain-Driven Design (DDD)** y **Clean Architecture**, y ha sido rigurosamente auditada y optimizada bajo los más altos estándares de **Performance** y **Seguridad (AppSec)**.

## 🚀 Características Principales

### 🏗️ Arquitectura Limpia & DDD
*   **Diseño por Capas:** Separación estricta entre **Domain** (lógica de negocio pura), **Application** (casos de uso) e **Infrastructure** (frameworks, base de datos).
*   **Invariantes de Dominio Protegidas:** Uso de factorías (`domain.NewUser`) para asegurar que el modelo de negocio jamás alcance estados inválidos (ej: validaciones Regex anti-Path Traversal / XSS pasivo).
*   **Inyección de Dependencias:** Total desacoplamiento usando interfaces, garantizando 100% de testabilidad.

### 🛡️ Seguridad Avanzada (AppSec Defensivo)
*   **Mitigación OOM (Out Of Memory):** Parsing protegido con `http.MaxBytesReader` (limitado a 10KB), truncando payloads anómalos en seco.
*   **Protección Slowloris & Keep-alive Floods:** Servidor HTTP configurado con `ReadTimeout (5s)`, `WriteTimeout (10s)` e `IdleTimeout (120s)`.
*   **Prevención CPU Starvation:** Verificaciones de longitud pre-bcrypt (máx. 72 chars) impidiendo ataques DoS por hashing de strings gigantes.
*   **Account Lockout:** Bloqueo progresivo de cuentas tras `domain.MaxFailedAttempts` intentos fallidos, con período de bloqueo configurable (`domain.LockDuration`).
*   **Protección PII — Email Cifrado:** Los emails se almacenan cifrados con **AES-256-GCM** (IV aleatorio). Para búsquedas se usa un **HMAC-SHA256** determinista, separando confidencialidad de buscabilidad sin exponer datos en claro.
*   **Rate Limiting por IP:** Las rutas de autenticación tienen un limitador estricto de 1 req/s con ráfagas de hasta 5, protegiendo bcrypt de ataques de fuerza bruta distribuidos.
*   **Secrets Zero-Trust:** Prohibición estricta de credenciales en código. Configurado íntegramente vía variables de entorno con validación en startup (fail-fast).

### ⚡ Performance & Alta Concurrencia
*   **Fat JWT (O(1) Authorization):** El middleware desempaqueta roles y permisos desde los `claims` del token en RAM, eliminando consultas N+1 a base de datos por cada request autenticado.
*   **Token Version Cache:** Un cache en memoria con TTL de 30 segundos valida `token_version` sin tocar Postgres en el caso feliz. Reduce la ventana de stale permissions de 15 minutos (TTL del JWT) a 30 segundos.
*   **Refresh Token Rotation:** Los Refresh Tokens son de uso único. Cada renovación borra el token anterior y emite uno nuevo, previniendo replay attacks.
*   **Time-Bound Contexts:** Todas las operaciones de DB usan `context.WithTimeout(ctx, 3s)` para prevenir bloqueos ante latencia de red.
*   **Control de Alocaciones:** Lógica GORM mapeada a DDD pre-alocando slices a su capacidad exacta.
*   **Paginación Nativa:** Implementada de extremo a extremo controlando consumo de Heap.

### 🗄️ Base de Datos
*   Motor: **PostgreSQL** (compatible con **Supabase**), usando `gorm.io/driver/postgres`.
*   Migraciones versionadas con `golang-migrate` (4 migraciones activas).

---

## 🛠️ Estructura del Proyecto

```text
├── cmd/
│   └── api/
│       └── main.go                          # Entrypoint: wiring de dependencias y bootstrap del servidor
│
├── internal/
│   ├── config/
│   │   └── config.go                        # Carga y valida todas las variables de entorno (fail-fast)
│   │
│   ├── domain/                              # 🔵 CORE — sin dependencias externas
│   │   ├── user.go                          # Entidad User, factory NewUser, lógica de lockout
│   │   └── role_repository.go              # Interfaces: UserRepository, RoleRepository (puertos)
│   │
│   ├── application/                         # 🟢 LÓGICA — orquesta domain + infrastructure
│   │   ├── auth_service.go                  # Register, Login, RefreshTokens, Logout
│   │   ├── auth_service_test.go
│   │   ├── user_service.go                  # GetMe, GetAll, CRUD de usuarios, AssignRoles
│   │   ├── user_service_test.go
│   │   ├── role_service.go                  # CRUD de roles, AssignPermissions
│   │   └── role_service_test.go
│   │
│   ├── infrastructure/
│   │   ├── cache/
│   │   │   └── token_version_cache.go       # Cache en memoria (sync.Map, TTL 30s) para token_version
│   │   ├── crypto/
│   │   │   └── encryptor.go                 # AES-256-GCM (cifrado) + HMAC-SHA256 (hash buscable) para PII
│   │   └── database/
│   │       ├── postgres.go                  # Conexión GORM + ejecución automática de migraciones
│   │       ├── gorm_models.go               # Modelos GORM (UserModel, RoleModel, etc.) — capa de mapeo
│   │       ├── user_repository.go           # Implementación de UserRepository
│   │       └── role_repository.go           # Implementación de RoleRepository
│   │
│   └── presentation/http/
│       ├── router.go                        # Registro de rutas, middlewares globales y Swagger UI
│       ├── handlers/
│       │   ├── auth_handler.go              # POST /register, /login, /refresh, /logout
│       │   ├── user_handler.go              # GET|POST|PUT|DELETE /users, GET /me
│       │   ├── role_handler.go              # CRUD /roles, /permissions, PUT /{id}/permissions
│       │   ├── health_handler.go            # GET /health/liveness, /health/readiness
│       │   └── helpers.go                   # Funciones utilitarias compartidas entre handlers
│       └── middleware/
│           ├── auth.go                      # RequireAuth (valida JWT + token_version), RequirePermission
│           ├── cors.go                      # Cabeceras CORS
│           ├── rate_limiter.go              # Rate limiter por IP (token bucket)
│           └── request_logger.go            # Logging estructurado de requests entrantes
│
├── migrations/                              # Migraciones SQL versionadas (golang-migrate)
│   ├── 000001_create_schema                 # Tablas base: users, roles, permissions, pivotes
│   ├── 000002_create_refresh_tokens         # Tabla refresh_tokens con índice único por token
│   ├── 000003_add_security_fields           # email_encrypted, email_hash, failed_attempts, locked_until
│   └── 000004_add_token_version             # token_version para invalidación inmediata de JWT
│
├── mocks/                                   # Mocks generados por mockery (no editar manualmente)
│   ├── mock_AuthService.go
│   ├── mock_UserService.go
│   ├── mock_RoleService.go
│   ├── mock_UserRepository.go
│   └── mock_RoleRepository.go
│
├── docs/                                    # Documentación del proyecto
│   ├── swagger.yaml / swagger.json          # Spec OpenAPI generada por swaggo
│   ├── docs.go                              # Inicializador de Swagger para Go
│   └── TESTING_ROADMAP.md                   # Avance de la suite de pruebas
│
├── scripts/
│   ├── test.ps1                             # Ejecuta la suite de tests (PowerShell)
│   └── coverage.ps1                         # Genera reporte de cobertura HTML (PowerShell)
│
├── generate.go                              # Directiva go:generate para invocar mockery
├── .mockery.yaml                            # Configuración de mockery (interfaces a mockear)
├── Makefile                                 # Targets: test, test-cov, generate, swag
├── go.mod / go.sum                          # Módulos y dependencias
└── .env                                     # Variables de entorno locales (no commitear)
```

---

## 💻 Configuración de Entorno Local

Copia el archivo `.env` y completa las siguientes variables:

| Variable | Requerida | Descripción |
|---|---|---|
| `JWT_SECRET` | ✅ | Clave HMAC para firmar JWTs. Mínimo 64 caracteres. |
| `DB_DSN` | ✅ | DSN de PostgreSQL para GORM. Ej: `postgresql://user:pass@host:5432/db` |
| `MIGRATION_DSN` | ✅ | DSN para golang-migrate (puede ser el mismo que `DB_DSN`). |
| `EMAIL_ENCRYPTION_KEY` | ✅ | Clave AES-256 para cifrar emails. Debe ser **exactamente 32 bytes**. |
| `PORT` | ➖ | Puerto del servidor. Default: `8080`. |
| `APP_ENV` | ➖ | Entorno de ejecución. Default: `development`. |

> La aplicación hace **fail-fast** en startup si alguna variable requerida falta o tiene formato inválido (ej: `EMAIL_ENCRYPTION_KEY` con longitud incorrecta).

---

## ▶️ Ejecución

```bash
# Instalar dependencias
go mod tidy

# Correr la API (las variables se leen del archivo .env automáticamente)
go run cmd/api/main.go
```

---

## 🌐 Endpoints

### Autenticación (sin token requerido)

| Método | Ruta | Descripción |
|---|---|---|
| `POST` | `/api/register` | Registro de usuario. Body: `{"username","password","email"}` |
| `POST` | `/api/login` | Login. Retorna `access_token` (Fat JWT, 15 min) + `refresh_token` (7 días) |
| `POST` | `/api/refresh` | Rota el refresh token y emite nuevos tokens |
| `POST` | `/api/logout` | Invalida todos los refresh tokens del usuario |

### Usuarios (requiere JWT)

| Método | Ruta | Permiso | Descripción |
|---|---|---|---|
| `GET` | `/api/me` | — | Perfil del usuario autenticado (sin I/O a DB) |
| `GET` | `/api/users` | `read:users` | Lista paginada de usuarios |
| `GET` | `/api/users/{id}` | `read:users` | Detalle de un usuario |
| `POST` | `/api/users` | `manage:users` | Crear usuario |
| `PUT` | `/api/users/{id}` | `manage:users` | Actualizar usuario |
| `DELETE` | `/api/users/{id}` | `manage:users` | Eliminar usuario |
| `PUT` | `/api/users/{id}/roles` | `manage:roles` | Asignar roles a un usuario |

### Roles y Permisos (requiere permiso `manage:roles`)

| Método | Ruta | Descripción |
|---|---|---|
| `GET` | `/api/roles` | Listar roles |
| `POST` | `/api/roles` | Crear rol |
| `GET` | `/api/roles/{id}` | Detalle de rol |
| `PUT` | `/api/roles/{id}` | Actualizar rol |
| `DELETE` | `/api/roles/{id}` | Eliminar rol |
| `PUT` | `/api/roles/{id}/permissions` | Asignar permisos a un rol |
| `GET` | `/api/permissions` | Listar permisos |
| `POST` | `/api/permissions` | Crear permiso |

### Healthchecks

| Método | Ruta | Descripción |
|---|---|---|
| `GET` | `/health/liveness` | Probe de liveness (Kubernetes/Docker) |
| `GET` | `/health/readiness` | Probe de readiness (verifica conexión a DB) |

### Documentación interactiva

La UI de Swagger está disponible en `/swagger/index.html` cuando la API está corriendo.

---

## 🧪 Testing & Tooling

```bash
# Correr todos los tests con race detector
make test

# Generar reporte de cobertura HTML
make test-cov

# Regenerar mocks (tras modificar interfaces en domain/ o application/)
make generate

# Regenerar documentación Swagger (tras modificar annotations en handlers/)
make swag
```

Los mocks en `mocks/` son generados automáticamente por [mockery](https://github.com/vektra/mockery) y **no deben editarse manualmente**. Ver `.mockery.yaml` para la configuración de interfaces mockeadas.

Para el estado actual de la suite de pruebas, ver [`docs/TESTING_ROADMAP.md`](docs/TESTING_ROADMAP.md).
