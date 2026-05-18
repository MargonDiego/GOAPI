# Diseño — Sistema de incidencias de convivencia escolar

**Fecha:** 2026-05-17
**Branch:** `feat/convivencia`
**Estado:** Diseño aprobado (brainstorming). Pendiente: plan de implementación.

---

## 1. Contexto y objetivo

Expandir la lógica de negocio de GOAPI (Clean Architecture + DDD en Go) con un sistema
de gestión de incidencias de **convivencia escolar** tipo JIRA: comentarios, adjuntos,
historial de cambios, asignación de responsables.

El sistema se alinea al marco legal chileno y a la ley de protección de datos. Principio
rector: **KISS pero profesional**, reutilizando la infraestructura existente en lugar de
reinventarla.

El **estudiante es solo un dato, nunca un usuario** (no autentica, no tiene login).

---

## 2. Marco legal chileno (resumen orientado al modelo)

- **Ley 20.536 sobre Violencia Escolar** y **Ley 21.128 "Aula Segura"**: obligan al
  establecimiento a investigar y resolver incidencias con debido proceso.
- **Política Nacional de Convivencia Escolar (MINEDUC)**: define el rol "Encargado de
  Convivencia Escolar" y el Reglamento Interno de Convivencia (RICE) — los plazos y la
  tipificación de faltas son **configurables por establecimiento**.
- **Debido proceso (irrenunciable, jurisprudencia anula sanciones sin él):** presunción
  de inocencia, derecho a descargos, resolución motivada, derecho a apelación,
  notificación al apoderado con acuse de recibo.
- **Clasificación de faltas:** `LEVE` / `GRAVE` / `GRAVISIMA`.
- **Medidas:** distinción legal entre **formativas/pedagógicas** y
  **disciplinarias/sancionatorias**. Expulsión y cancelación de matrícula reservadas a
  faltas gravísimas (Aula Segura).
- **Plazos:** configurables por RICE. Límites legales duros: investigación Aula Segura
  ≤ 10 días hábiles; denuncia de delito ≤ 24 h.
- **Ley 21.719 (protección de datos, vigente 1-dic-2026):** el expediente completo es
  dato sensible de NNA (menores). Exige medidas de seguridad, control de acceso, log de
  acceso, retención acotada a la finalidad. **Base de licitud: cumplimiento de obligación
  legal** (Ley 20.536) — NO consentimiento; por lo tanto no se modela entidad de
  consentimiento.

Fuentes completas en la sección 11.

---

## 3. Alcance

### Dentro de v1 (Núcleo + debido proceso)

Estudiante, Incidencia con máquina de estados, Comentarios, Adjuntos, Historial legal
inmutable, asignación de responsable, Medidas (formativa/disciplinaria), Descargos,
Resolución motivada, Apelación, Notificación con acuse. Plazos como **fechas manuales**.

### Fuera de v1 (diferido, no se cierra la puerta)

- Motor de plazos configurable con cálculo de días hábiles y alertas (cron).
- Importación masiva de estudiantes desde sistema externo (SIGE u otro).
- Protocolos especiales auto-disparados; entidad de notificación de brechas.
- Multi-parte: múltiples NNA involucrados por incidencia (v1: un estudiante principal).
- Read models / reportería transversal (CQRS-lite) — se introduce cuando exista la
  necesidad real.

---

## 4. Decisiones de diseño (tomadas en brainstorming)

| # | Decisión | Razón |
|---|---|---|
| 1 | Dominio: convivencia escolar (no genérico) | El marco legal define el modelo |
| 2 | Alcance v1: Núcleo + debido proceso | El debido proceso es legalmente irrenunciable |
| 3 | Estudiante: alta manual, ficha mínima, diseñado para import futuro | Minimización de datos (Ley 21.719) + KISS |
| 4 | Adjuntos: disco local + metadata en BD, UUID, descarga vía endpoint con RBAC | KISS, sin dependencias nuevas |
| 5 | Enfoque: expediente normalizado (entidades tipadas separadas) | Hace cumplir invariantes de debido proceso de forma testeable |
| 6 | `Notificacion`: entidad propia con `Acuse bool` | El acuse de recibo es carga legal del debido proceso |
| 7 | `IncidenciaRepository` como raíz de agregado (2 repos, no per-entity) | La frontera de consistencia = integridad legal del expediente; decisión reversible/aditiva |
| 8 | Capa narrativa: cifrado en reposo a nivel infra + RBAC + auditoría | Mantiene búsqueda; identidad del menor sí va cifrada a nivel app; KISS defendible |
| 9 | `AuditLog` existente solo para auditoría de seguridad/acceso; `IncidenciaEvento` = historial legal | Audiencias y retención diferenciadas (Ley 21.719) |

---

## 5. Modelo de dominio (`internal/domain/`)

Structs puros (sin tags GORM), factories `NewX` con invariantes, métodos de dominio para
reglas de negocio — siguiendo el patrón de `User.RecordFailedAttempt`.

### 5.1 Entidades

**`Estudiante`** — solo dato, nunca usuario.
- `RutEncrypted` (AES-256-GCM) + `RutHash` (HMAC, índice único, búsqueda)
- `NombreEncrypted` (AES, solo display)
- `Curso` (texto plano, para filtrar) · `Scope` (establecimiento) · soft delete
- Factory valida RUT chileno (módulo 11). Diseñada para que un import futuro sea otro
  caller de la misma factory.

**`Incidencia`** — raíz del agregado; máquina de estados en el dominio.
- `Codigo` (`INC-2026-0001`, único por scope) · `EstudianteID` (involucrado principal)
- `Titulo` · `Descripcion` (relato, sensible) · `Gravedad` (LEVE/GRAVE/GRAVISIMA)
- `Categoria` (maltrato_entre_estudiantes / maltrato_adulto_estudiante / ciberacoso /
  vulneracion_derechos / connotacion_sexual / porte_arma / consumo / otro)
- `EsConstitutivoDeDelito` (bool, solo se almacena y expone) · `Estado`
- `DenuncianteID` · `ResponsableID` (*uint, Encargado) · `Scope`
- `SuspensionPreventiva` (bool) + `FechaSuspensionPreventiva` (*time) — Aula Segura,
  modelado como flag, NO estado paralelo
- `FechaRecepcion` · `FechaInicioInvestigacion` (*time) · `FechaCierre` (*time)
- `FechaEliminacionProgramada` (*time, retención Ley 21.719, manual) · soft delete

**`Comentario`** — hilo append-only (inmutable): `IncidenciaID`, `AutorID`, `Cuerpo`, `CreatedAt`.

**`Adjunto`** — `IncidenciaID`, `NombreOriginal`, `NombreAlmacenado` (UUID), `MimeType`,
`TamanoBytes`, `HashSHA256`, `SubidoPorID`, `CreatedAt`.

**`Medida`** — `IncidenciaID`, `Clase` (FORMATIVA/DISCIPLINARIA), `Tipo`
(dialogo/servicio/suspension/condicionalidad/cancelacion/expulsion), `Descripcion`,
`Proporcionalidad` (texto, **obligatorio** por factory), `ResponsableEjecucionID`,
`FechaInicio`, `FechaTermino` (*time), `EstadoCumplimiento`
(PENDIENTE/EN_CURSO/CUMPLIDA/INCUMPLIDA).
Invariante: expulsión/cancelación solo si `Gravedad=GRAVISIMA`.

**`Descargo`** — derecho a ser oído: `IncidenciaID`, `PresentadoPorID`, `Contenido`,
`FechaPresentacion`, `CreatedAt`.

**`Resolucion`** — decisión motivada: `IncidenciaID`, `Tipo` (ORIGINAL/APELACION),
`Fundamentacion` (**obligatorio, factory rechaza vacío**), `Decision`, `ResueltoPorID`,
`FechaResolucion`, `CreatedAt`.

**`Apelacion`** — `IncidenciaID`, `ResolucionID`, `PresentadaPorID`, `Motivo`,
`FechaPresentacion`, `PlazoVencimiento` (fecha concreta almacenada), `Estado`
(PENDIENTE/ACEPTADA/RECHAZADA), `CreatedAt`.

**`Notificacion`** — debido proceso: `IncidenciaID`, `Destinatario`, `Medio`,
`Contenido`, `FechaNotificacion`, `Acuse` (bool), `FechaAcuse` (*time), `CreatedAt`.

**`IncidenciaEvento`** — historial inmutable = **expediente legal** (audiencia:
apoderado/Superintendencia). `IncidenciaID`, `Tipo` (CREACION/CAMBIO_ESTADO/ASIGNACION/
COMENTARIO/ADJUNTO/MEDIDA/DESCARGO/RESOLUCION/APELACION/NOTIFICACION), `ActorID`,
`Resumen`, `EstadoAnterior` (*string), `EstadoNuevo` (*string), `CreatedAt`.
**Sin IP/UA** — eso vive en `AuditLog` (separación para retención diferenciada).

### 5.2 Máquina de estados (en el dominio, con guardas)

```
RECIBIDA ──► EN_INVESTIGACION ──► RESUELTA ──► EN_APELACION ──► RESOLUCION_FINAL ──► EN_SEGUIMIENTO ──► CERRADA
                   │                  │
                   └──► DERIVADA      └──► EN_SEGUIMIENTO (sin apelación o plazo vencido)
```

Guardas como métodos de dominio (testeables sin infra):
- `→ EN_INVESTIGACION`: requiere `ResponsableID` + `FechaInicioInvestigacion`
- `→ RESUELTA`: requiere ≥1 `Resolucion` con `Fundamentacion` no vacía
- `→ EN_APELACION`: requiere `Apelacion` dentro de plazo
- `→ RESOLUCION_FINAL`: requiere `Resolucion` tipo APELACION
- `→ CERRADA`: prohibido con apelación PENDIENTE

Cada transición emite un `IncidenciaEvento`.

### 5.3 Errores tipados nuevos (`domain/errors.go`, patrón `AppError`)

`ErrIncidenciaNotFound` (404) · `ErrEstudianteNotFound` (404) ·
`ErrTransicionInvalida` (409) · `ErrResolucionSinFundamento` (400) ·
`ErrApelacionFueraDePlazo` (409) · `ErrMedidaDesproporcionada` (400) ·
`ErrRutInvalido` (400).

---

## 6. Capas

### 6.1 Repositorios (`domain/`, interfaces segregadas Reader/Writer)

- **`EstudianteRepository`**: `FindByID`, `FindByRutHash`, `Search` (curso + scope),
  `Create`, `Update`, `Delete`, `Restore`, contadores + variantes `ByScope`.
- **`IncidenciaRepository`** (raíz de agregado, gestiona incidencia + expediente):
  `FindByID`, `FindByCodigo`, `Search` (filtros estado/gravedad/categoría/responsable/
  estudiante/scope), `Create`, `UpdateEstado`, `AsignarResponsable`, `AppendComentario`,
  `AppendAdjunto`, `AppendMedida`, `AppendDescargo`, `AppendResolucion`,
  `AppendApelacion`, `AppendNotificacion`, `AppendEvento`, listados por incidencia,
  contadores. Segregable en `IncidenciaReader` / `IncidenciaWriter` cuando crezca.

Decisión 7: dos repos en lugar de diez. La frontera de consistencia coincide con la
integridad legal del expediente (ej: `Resolver` = crear `Resolucion` + cambiar `Estado` +
emitir `IncidenciaEvento`, atómico). Reversible y aditivo si un hijo necesitara ciclo de
vida independiente.

### 6.2 Servicios (`application/`, inyección por constructor)

- **`EstudianteService`**: CRUD con cifrado PII (usa `Encryptor`), enforcement de scope,
  `audit.log` (= log de acceso Ley 21.719, incluye lecturas).
- **`IncidenciaService`** (orquestador): `Crear`, `Asignar`, `IniciarInvestigacion`,
  `AgregarComentario`, `AdjuntarArchivo`, `RegistrarDescargo`, `RegistrarMedida`,
  `Resolver`, `RegistrarNotificacion`, `PresentarApelacion`, `ResolverApelacion`,
  `Derivar`, `IniciarSeguimiento`, `Cerrar`. Cada método delega la guarda de transición
  al dominio, emite `IncidenciaEvento`, llama `audit.log`.

### 6.3 Puerto de almacenamiento (hexagonal)

- **`FileStorage`** (interface en `domain/`): `Save(ctx, reader, meta) (storedName, err)`,
  `Open(ctx, storedName) (io.ReadCloser, err)`, `Delete(ctx, storedName) error`.
- Implementación `LocalFileStorage` en `infrastructure/storage/` (volumen, UUID). El
  dominio nunca toca el disco.

### 6.4 Extensión del `Encryptor` (mínima)

Añadir genéricos `Encrypt(plaintext) (string, error)`, `Decrypt(ciphertext) (string, error)`,
`Hash(value) string`. Los actuales `EncryptEmail/DecryptEmail/HashEmail` delegan en ellos.
Cero crypto nueva. Se usa para `Estudiante.Rut`/`Nombre`.

### 6.5 Presentación (`presentation/rest/`, reutiliza middleware actual)

- **DTOs** (`handlers/dto.go`): nunca exponen campos `*Encrypted` crudos. RUT/nombre se
  descifran solo en respuestas autorizadas.
- **Permisos RBAC nuevos**: `read:incidencias`, `manage:incidencias`,
  `resolve:incidencias`, `read:estudiantes`, `manage:estudiantes`.
- **Roles** "EncargadoConvivencia" y "Director": son datos, se crean vía el endpoint de
  roles existente (seed opcional). No se hardcodean.
- **Rutas**: `/api/v1/estudiantes` y `/api/v1/incidencias` (+ subrecursos). Rutas fijas
  antes de `/{id}` (patrón del router actual). Detrás de `RequireAuth` +
  `RequirePermission`, CSRF en mutaciones, rate limiter global.
- **Descarga de adjuntos**: `GET /api/v1/incidencias/{id}/adjuntos/{adjId}` — streaming
  tras verificar RBAC + scope.

---

## 7. Protección de datos (Ley 21.719)

- **Capa identidad (cifrado a nivel app):** `Estudiante.Rut` (AES + HMAC),
  `Estudiante.Nombre` (AES). Mismo patrón email existente.
- **Capa narrativa (cifrado en reposo a nivel infra + RBAC + auditoría):**
  `Incidencia.Descripcion`, `Comentario.Cuerpo`, `Descargo.Contenido`,
  `Resolucion.Fundamentacion`. Texto legible en BD (mantiene búsqueda); medio físico
  cifrado por el volumen/Postgres. Riesgo residual aceptado: un dump lógico desde sistema
  corriendo expondría el texto (no la identidad del menor).
- **Log de acceso:** el patrón `audit.log` se extiende para registrar **lecturas** de
  `Estudiante`/`Incidencia` (quién leyó datos de qué menor, cuándo).
- **Retención:** `FechaEliminacionProgramada` almacenada (manual en v1, sin cron).
- **Separación de auditorías:** `IncidenciaEvento` = expediente legal (sin IP/UA);
  `AuditLog` = seguridad (con IP/UA). Retenciones diferenciadas.
- **Base de licitud:** cumplimiento de obligación legal (Ley 20.536), NO consentimiento.
  No se modela entidad de consentimiento — reducción de alcance justificada por ley.

---

## 8. Persistencia (`infrastructure/persistence/`)

- Modelos GORM espejo en **archivo nuevo `convivencia_models.go`** (no inflar
  `gorm_models.go`) + mappers `toDomainX`/`toDBX` siguiendo el patrón exacto.
- **Migraciones golang-migrate** (archivos SQL versionados en `migrations/`, la última
  es `000008`). NO se usa AutoMigrate — el proyecto corre `migrate.New("file://migrations")`
  en `postgres.go`. Las tablas nuevas se crean con archivos `000009_*.up.sql`/`.down.sql`
  y siguientes.
- Índices: `estudiante.rut_hash` único · `incidencia.codigo` único por scope · FKs
  `incidencia_id` · índices `scope` y `estado`.
- Implementaciones de repos con `context.WithTimeout(3s)` como los repos actuales.

---

## 9. Estrategia de testing (Strict TDD activo)

- **Dominio:** tests table-driven sin infra (factory rechaza RUT inválido, `Resolucion`
  rechaza `Fundamentacion` vacía, guardas de máquina de estados) — estilo `user_test.go`.
- **Aplicación:** servicios con mocks generados (mockery, como `mocks/`). Test primero.
- **Infraestructura:** repos + `LocalFileStorage` con Postgres real, estilo
  `repository_integration_test.go`.
- **Presentación:** handlers con `httptest`, estilo `auth_handler_test.go`.
- Red-green-refactor obligatorio durante la implementación.

---

## 10. Reutilización de infraestructura existente (no reinventar)

| Necesidad | Infraestructura existente reutilizada |
|---|---|
| Historial de cambios (seguridad) | `AuditLog` + patrón `audit.log()` |
| PII del estudiante | Patrón doble representación AES-256-GCM + HMAC (hoy email) |
| Asignación de responsables | RBAC roles/permisos + `token_version` |
| Aislamiento institucional | `Scope` (multi-tenant) + `assertScopeAccess` |
| Borrado seguro | Soft delete + `Restore` (gorm.Model) |
| Errores HTTP tipados | `AppError` (code/message/status) |
| Paginación | `PaginatedResult[T]` |

---

## 11. Fuentes (marco legal chileno)

- Ley 20.536 sobre Violencia Escolar — BCN LeyChile: https://www.bcn.cl/leychile/navegar?idNorma=1030087
- Ley 21.128 "Aula Segura" — BCN LeyChile: https://www.bcn.cl/leychile/navegar?idNorma=1127100
- Política Nacional de Convivencia Educativa 2024–2030 (MINEDUC): https://convivenciaparaciudadania.mineduc.cl/wp-content/uploads/2024/05/Politica-Nacional-de-Convivencia-Educativa-MINEDUC-2024.pdf
- Debido proceso e interés superior del niño en procedimientos disciplinarios escolares (Scielo): https://www.scielo.cl/scielo.php?script=sci_arttext&pid=S0719-21502023000100301
- Ley 21.719 — BCN LeyChile: https://www.bcn.cl/leychile/navegar?idNorma=1209272
- Guía práctica implementación nueva ley de datos personales (Gobierno Digital): https://wikiguias.digital.gob.cl/datos-personales/guia-practica-implementacion-nueva-ley-datos-personales
- Jira workflows: statuses, transitions, conditions/validators (Atlassian): https://support.atlassian.com/jira-cloud-administration/docs/configure-advanced-issue-workflows/
