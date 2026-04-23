# Go API Server - Clean Architecture (Production-Ready)

Este proyecto es una API REST escalable y de alto rendimiento construida en Go (Golang). Implementa principios de **Domain-Driven Design (DDD)** y **Clean Architecture**, y ha sido rigurosamente auditada y optimizada bajo los más altos estándares de **Performance** y **Seguridad (AppSec)**.

## 🚀 Características Principales

### 🏗️ Arquitectura Limpia & DDD
*   **Diseño por Capas:** Separación estricta entre **Domain** (lógica de negocio pura), **Application** (casos de uso) e **Infrastructure** (frameworks, base de datos).
*   **Invariantes de Dominio Protegidas:** Uso de factorías (`domain.NewUser`) para asegurar que el modelo de negocio jamás alcance estados inválidos (Ej: Validaciones estrictas Regex *Anti-Path Traversal / XSS* pasivo).
*   **Inyección de Dependencias:** Total desacoplamiento usando interfaces, garantizando 100% de testabilidad.

### 🛡️ Seguridad Avanzada (AppSec Defensivo)
*   **Mitigación OOM (Out Of Memory):** Parsing protegido con `http.MaxBytesReader` (limitado a 10KB para contraseñas/usernames), truncando payloads anómalos o maliciosos en seco.
*   **Protección Slowloris & Keep-alive Floods:** Servidor HTTP instanciado manualmente con `ReadTimeout (5s)`, `WriteTimeout (10s)` e `IdleTimeout (120s)`.
*   **Prevención CPU Starvation:** Verificaciones de longitud `PRE-BCrypt` restrictivas impidiendo bombardeos DOS triturando megabytes de texto.
*   **Secrets Zero-Trust:** Prohibición estricta de credenciales en código. Configurado íntegramente vía Variables de Entorno.

### ⚡ Performance & Alta Concurrencia
*   **Fat JWT (O(1) Authorization):** El middleware de Autorización desempaqueta y construye roles mediante los `claims` en RAM, suprimiendo las consultas `N+1` costosas a base de datos. Complejidad **CERO I/O** por cada visita segura en la API.
*   **Time-Bound Contexts:** Propagación de fallos asíncronos en queries de red. La DB es interrumpida y limpiada por el *Garbage Collector* con `context.WithTimeout(ctx, 3*time.Second)` si la red experimenta cuellos de botella lentos.
*   **Control de Alocaciones (Allocations):** Lógica GORM mapeada de vuelta a DDD pre-alocando `Slices` a su capacidad exacta.
*   **Paginación Nativa:** Implementada de extremo a extremo controlando consumo de Heap.

### 🗄️ Base de Datos
*   Motor default: **PostgreSQL** adaptado estéticamente a **Supabase**, usando el pull estricto `gorm.io/driver/postgres`.

---

## 🛠️ Estructura del Proyecto

```text
├── cmd/
│   └── api/
│       └── main.go                  # Entrypoint: Inyección y Bootstrapping general
├── internal/
│   ├── domain/                      # 🔵 CORE: Entidades (User, Role, Permission) y Puertos (Interfaces)
│   ├── application/                 # 🟢 LÓGICA: Servicios orquestadores (AuthService, UserService)
│   ├── infrastructure/              # 🔴 EXTERNO: Conexión PSQL (GORM) y Repositorios
│   └── presentation/http/           # 🔴 RED: Enrutadores (Mux), Handlers JSON, Fat JWT Middleware
├── .env.example                     # Plantilla segura de variables (JWT_SECRET, DB_DSN, etc.)
└── go.mod                           # Módulos y dependencias (Go 1.21)
```

---

## 💻 Configuración de Entorno Local

1. Crea variables de entorno copiando el archivo `/.env.example` localmente.
2. Necesitarás:
   *   `JWT_SECRET`: Una key criptográfica > 64 caracteres.
   *   `DB_DSN`: Endpoint de Supabase O PostgreSQL compatible (Ej: `postgresql://postgres:PASSWORD@db.../postgres`).
   *   `PORT`: `8080` (Por Opción Default).

## ▶️ Ejecución

```bash
# Sincroniza e instala silenciosamente todos los drivers (Gorilla Mux, JWT, Gorm Postgres)
go mod tidy

# Corre la API inyectando variables seguras (Windows/Unix/Mac):
JWT_SECRET="MySecret64BitLong" DB_DSN="postgresql://postgres:pass@db...:5432/postgres" PORT="8080" go run cmd/api/main.go
```

## 🌐 Endpoints Principales

- `POST /api/register`
   -  Body JSON: `{"username": "tu", "password":"123"}` -> Payload máx 10KB, Regex alfanumérico.
- `POST /api/login`
   - Payload `AuthRequest`. Retorna un Bearer **Fat JWT**.
- `GET /api/me`
   - Headers: `Authorization: Bearer <TKN>`. Retorna DTO seguro del Session Object en Memoria RAM O(0 DB).
- `GET /api/users?page=1&size=5`
   - Headers: `Authorization: Bearer <TKN>`. Filtro Activo: Requiere Claim Permiso `read:users`. Paginación defensiva.