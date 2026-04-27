# Roadmap de Testing - Go API

Este documento rastrea el avance de la implementación de la suite de pruebas bajo estándares Enterprise.

## 🏁 Estado de Avance

- [x] **Fase 1: Tooling y Automatización Base**
  - [x] Integración de `mockery` para generación de mocks.
  - [x] Creación de `Makefile` (`make test`, `make test-cov`, `make generate`) y alternativas PS1.
  - [x] Configuración de librería `testify`.

- [x] **Fase 2: Unit Testing Core**
  - [x] `AuthService` (Lógica de cifrado, rate limiting).
  - [x] `UserService` (CRUD y asignación de roles).
  - [x] `RoleService` (Manejo de permisos).
  - [x] `AuthHandler` y Middlewares (`RequireAuth`, `RequirePermission`) con `httptest`.
  - [x] `UserHandler` / `RoleHandler` (con `httptest`).

- [ ] **Fase 3: Integration Testing (Infraestructura)**
  - [ ] Setup de `testcontainers-go` (PostgreSQL efímero).
  - [ ] Cobertura de `user_repository`.
  - [ ] Cobertura de `role_repository`.

- [ ] **Fase 4: Pruebas E2E (End-To-End)**
  - [ ] Setup de `httptest.NewServer`.
  - [ ] Flujo de Registro -> Login -> Obtención de JWT.
  - [ ] Flujo de Acceso a rutas protegidas por roles.

- [ ] **Fase 5: Calidad en CI/CD**
  - [ ] Workflow de GitHub Actions (`ci.yml`).
  - [ ] Regla estricta de cobertura mínima (80%).
  - [ ] Ejecución con `-race` detector obligatorio.
