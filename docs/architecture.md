# Arquitectura del proyecto

Este documento explica las decisiones de diseño no triviales del proyecto: el *por qué* detrás de cada elección técnica. Es el complemento a la documentación inline del código y al README.

---

## 1. Estructura de capas (Clean Architecture + DDD)

El proyecto sigue una arquitectura de capas con una regla de dependencia estricta: **las capas internas no conocen a las externas**.

```
domain  ←  application  ←  infrastructure
                         ←  presentation/http
```

**Domain** no importa nada externo a Go stdlib. Contiene las entidades (`User`, `Role`, `Permission`), las interfaces de los repositorios (puertos), las constantes de negocio (`MaxFailedAttempts`, `LockDuration`) y la lógica de dominio pura (`IsLocked`, `RecordFailedAttempt`). Todo lo que vive aquí puede testearse sin base de datos, sin HTTP, sin ningún framework.

**Application** contiene los servicios que orquestan el dominio: `AuthService`, `UserService`, `RoleService`. Depende de las interfaces de `domain`, nunca de implementaciones concretas. Esto hace que los tests de servicios usen mocks generados automáticamente en lugar de una base de datos real.

**Infrastructure** contiene las implementaciones concretas: repositorios GORM, el encryptor AES, el cache de token_version. Implementa las interfaces definidas en `domain`.

**Presentation** contiene los handlers HTTP y los middlewares. Solo traduce HTTP ↔ aplicación: deserializa el request, llama al servicio, serializa la respuesta. No contiene lógica de negocio.

La ventaja práctica de este diseño es que cada capa puede cambiarse de forma independiente. Reemplazar PostgreSQL por otro motor requiere solo reescribir `infrastructure/database/` sin tocar el dominio ni los handlers.

---

## 2. Autorización: Fat JWT + token_version

### El problema
Un JWT estándar con TTL de 15 minutos tiene un window de permisos stale: si un admin revoca los permisos de un usuario, ese usuario puede seguir operando hasta que el token expire. En un sistema RBAC esto es inaceptable.

La solución naive es validar permisos contra la base de datos en cada request, pero eso introduce una query adicional por cada llamada autenticada — inaceptable en producción.

### La solución adoptada
El sistema usa dos mecanismos en conjunto:

**Fat JWT:** El token embebe los permisos del usuario como claim `permissions` en el momento del login. El middleware de autorización lee el claim directamente desde el token en RAM, sin tocar Postgres. La complejidad de autorización es O(1) sin I/O.

**token_version:** La entidad `User` tiene un campo `token_version` (entero, default 1) que se incrementa cada vez que cambian los roles o permisos del usuario. El JWT embebe este valor como claim `ver`. El `AuthMiddleware` compara `JWT.ver` contra `DB.token_version` en cada request. Si no coinciden, devuelve 401 y fuerza re-autenticación.

**Token Version Cache:** La comparación `JWT.ver == DB.token_version` requeriría un SELECT por request si se hiciera directo a Postgres. Para evitarlo, `TokenVersionCache` almacena la versión en memoria con un TTL de 30 segundos. En el caso feliz (sin cambios de permisos recientes), el middleware resuelve el check desde RAM. Cuando se asignan o revocan roles/permisos, se llama a `cache.Invalidate(userID)` para que el próximo request fuerce la re-lectura desde DB. La ventana máxima de stale permissions pasa de 15 minutos (TTL del JWT) a 30 segundos (TTL del cache).

```
Login exitoso
  → JWT embebe: { sub, uid, ver: token_version, permissions[], exp }

Request autenticado
  → Middleware parsea JWT
  → Lee token_version del cache (o DB si no está en cache)
  → Si JWT.ver != DB.ver → 401
  → Si JWT.ver == DB.ver → inyecta UserSession en contexto, continúa

Admin cambia roles de usuario X
  → DB: INCREMENT users.token_version WHERE id = X
  → Cache: Invalidate(X)
  → Próximo request de X: cache miss → lee DB → JWT.ver (viejo) != DB.ver (nuevo) → 401
```

---

## 3. Protección de PII: email con doble representación

### El problema
Cifrar un campo con un IV aleatorio (como hace AES-GCM correctamente) produce ciphertexts diferentes para el mismo plaintext. Esto hace imposible hacer `WHERE email = ?` en la base de datos. Pero usar IV fijo compromete la seguridad del cifrado (ciphertext determinista = vulnerable a análisis de frecuencia).

### La solución adoptada
Cada email se almacena en dos columnas:

**`email_encrypted`** — cifrado con AES-256-GCM usando un nonce aleatorio de 12 bytes. Se usa únicamente para mostrar el email al usuario cuando lo pide. Cada llamada a `EncryptEmail` produce un resultado diferente.

**`email_hash`** — HMAC-SHA256 del email usando la misma clave de 32 bytes. Es determinista: el mismo email siempre produce el mismo hash. Se usa como índice único en Postgres para verificar unicidad (`WHERE email_hash = ?`) y para búsquedas. Al usar HMAC en lugar de SHA256 puro, la clave actúa como secreto: una tabla de hashes robada es inútil sin conocer `EMAIL_ENCRYPTION_KEY`.

```
Register("user@example.com")
  → email_hash     = HMAC-SHA256(email, key)    → índice único en DB
  → email_encrypted = AES-256-GCM(email, key, nonce_aleatorio) → almacenado en DB

GET /api/me
  → DecryptEmail(user.EmailEncrypted) → "user@example.com" → devuelto al usuario
```

La entidad de dominio `User` nunca recibe el email en texto plano desde la base de datos. El descifrado ocurre en la capa de servicio solo cuando es necesario para responder al cliente.

---

## 4. Account Lockout en el dominio

La lógica de bloqueo de cuenta (`IsLocked`, `RecordFailedAttempt`, `ResetFailedAttempts`) vive en la entidad `User` del dominio, no en el servicio.

La razón es que esta es una invariante de negocio pura: una cuenta bloqueada está bloqueada independientemente del framework, la base de datos o el protocolo de red. Al ubicar la lógica en el dominio, puede testearse de forma directa e instantánea sin mocks ni infraestructura.

Los parámetros de configuración (`MaxFailedAttempts = 5`, `LockDuration = 15 min`) son constantes exportadas en `domain` para que los tests puedan referenciarlas sin hardcodear valores mágicos.

El `AuthService.Login` aplica el lockout en este orden deliberado: primero verifica si la cuenta está bloqueada, *luego* compara la contraseña. Esta secuencia evita un timing attack donde un atacante puede inferir si las credenciales son correctas basándose en si el error es "cuenta bloqueada" vs "credenciales inválidas".

---

## 5. Refresh Token Rotation

Los Refresh Tokens implementan rotación estricta (RFC 6749 best practice):

1. Al recibir un Refresh Token válido, se **borra inmediatamente** de la base de datos antes de emitir el nuevo par.
2. Se emite un nuevo Access Token y un nuevo Refresh Token.
3. Si el mismo Refresh Token se usa dos veces (señal de robo), la segunda llamada falla con `ErrInvalidToken` porque el token ya no existe en DB.

El nuevo Access Token incorpora la `token_version` actual del usuario en DB, lo que significa que un refresh también "recoge" cualquier cambio de permisos que haya ocurrido desde el login original.

---

## 6. Modelos GORM separados de las entidades de dominio

La base de datos usa modelos GORM (`UserModel`, `RoleModel`, etc.) definidos en `infrastructure/database/gorm_models.go`, que son distintos de las entidades del dominio (`domain.User`, `domain.Role`, etc.).

Esto es una capa anti-corrupción deliberada. Las entidades de dominio son representaciones puras del negocio: no tienen tags de struct, no dependen de GORM, no conocen las tablas de la base de datos. Los modelos GORM son adaptadores de persistencia: manejan la relación Many-to-Many a través de `gorm.Model`, los nombres de tabla, y las asociaciones.

Los repositorios en `infrastructure/database/` hacen el mapeo en ambas direcciones: domain → GORM al escribir, GORM → domain al leer. El costo es algo de código de mapeo adicional; el beneficio es que cambiar el ORM o el esquema de la base de datos no requiere modificar el dominio.

---

## 7. Decisiones de seguridad HTTP

**Pre-bcrypt length check:** `Login` y `Register` rechazan contraseñas mayores a 72 caracteres antes de llamar a bcrypt. bcrypt silenciosamente trunca los inputs a 72 bytes, pero procesar strings de varios megabytes para llegar a esa truncación es costoso en CPU. Un atacante puede enviar payloads gigantes para saturar el servidor.

**MaxBytesReader:** El parser de JSON de los handlers está limitado a 10KB mediante `http.MaxBytesReader`. Payloads anómalos son truncados en la lectura antes de llegar al decoder.

**Timeouts del servidor HTTP:** `ReadTimeout: 5s`, `WriteTimeout: 10s`, `IdleTimeout: 60s`. Configurados manualmente en `http.Server` para prevenir conexiones keepalive maliciosas (Slowloris).

**Rate Limiter en autenticación:** Las rutas `/register`, `/login`, `/refresh` y `/logout` tienen un rate limiter de 1 req/s por IP con ráfagas de hasta 5. Esto hace que los ataques de fuerza bruta a bcrypt sean imprácticos incluso si el account lockout no estuviera activo.

**context.WithTimeout en todas las operaciones de DB:** Cada llamada a repositorio usa `context.WithTimeout(ctx, 3*time.Second)`. Esto garantiza que una base de datos lenta o una conexión de red degradada no bloquee goroutines indefinidamente.

---

## 8. Bootstrap y Graceful Shutdown

El `main.go` inicializa las dependencias en orden explícito (config → DB → repos → servicios → handlers → router) y las pasa por inyección de dependencias. No hay singletons globales ni `init()` con efectos secundarios.

El servidor escucha `SIGINT` y `SIGTERM` para hacer graceful shutdown: espera hasta 10 segundos para que los requests en curso terminen antes de cerrar la conexión a la base de datos. Esto garantiza un cierre limpio tanto en desarrollo (Ctrl+C) como en Kubernetes (SIGTERM del scheduler).

---

## 9. Logging

El proyecto usa [zerolog](https://github.com/rs/zerolog) para logging estructurado. En `development` los logs se formatean en modo consola (legibles). En `production` se emiten como JSON puro para ingesta por sistemas de log (Datadog, CloudWatch, etc.). El nivel de log se controla con `APP_ENV`.
