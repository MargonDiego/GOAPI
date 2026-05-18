# Plan A — Estudiante (vertical slice) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Entregar un CRUD de `Estudiante` (solo dato, no usuario) con PII cifrada (RUT/nombre), aislamiento por scope y auditoría de acceso, como base reutilizable para el Plan B (incidencias).

**Architecture:** Clean Architecture + DDD. Vertical slice completo: dominio puro (validación RUT módulo 11) → extensión genérica del `Encryptor` → puerto `EstudianteRepository` → `EstudianteService` → modelo GORM + mappers + migración SQL → handler + DTOs + RBAC + rutas + wiring. Sigue exactamente los patrones existentes de `User`.

**Tech Stack:** Go 1.25, GORM, PostgreSQL, golang-migrate (archivos SQL versionados), gorilla/mux, mockery v2, testify, zerolog, validator/v10.

**Spec de referencia:** `docs/superpowers/specs/2026-05-17-convivencia-incidencias-design.md`

---

## File Structure

| Archivo | Responsabilidad | Acción |
|---|---|---|
| `internal/domain/errors.go` | Errores tipados | Modificar (agregar 2 errores) |
| `internal/domain/estudiante.go` | Entidad `Estudiante` + factory + `ValidarRut` | Crear |
| `internal/domain/estudiante_test.go` | Tests puros de dominio | Crear |
| `internal/domain/estudiante_repo.go` | Puerto `EstudianteRepository` | Crear |
| `internal/infrastructure/crypto/encryptor.go` | Cifrado genérico PII | Modificar |
| `internal/infrastructure/crypto/encryptor_test.go` | Tests del encryptor genérico | Crear |
| `internal/application/estudiante_service.go` | Lógica de negocio + cifrado + scope + auditoría | Crear |
| `internal/application/estudiante_service_test.go` | Tests de servicio con mocks | Crear |
| `.mockery.yaml` | Config de mocks | Modificar (agregar interfaz) |
| `mocks/mock_EstudianteRepository.go` | Mock generado | Generar |
| `internal/infrastructure/persistence/convivencia_models.go` | Modelo GORM + mappers | Crear |
| `internal/infrastructure/persistence/estudiante_repository.go` | Impl GORM del puerto | Crear |
| `internal/infrastructure/persistence/estudiante_repository_integration_test.go` | Test de integración con Postgres | Crear |
| `migrations/000009_create_estudiantes.up.sql` | DDL tabla | Crear |
| `migrations/000009_create_estudiantes.down.sql` | Rollback DDL | Crear |
| `internal/infrastructure/persistence/postgres.go` | Seed de permisos | Modificar (`seedDefaults`) |
| `internal/presentation/rest/handlers/estudiante_handler.go` | Handler HTTP + DTOs | Crear |
| `internal/presentation/rest/handlers/estudiante_handler_test.go` | Tests de handler (httptest) | Crear |
| `internal/presentation/rest/router.go` | Rutas | Modificar (firma + rutas) |
| `cmd/api/main.go` | Wiring de dependencias | Modificar |

---

## Task 1: Errores tipados de dominio

**Files:**
- Modify: `internal/domain/errors.go`

- [ ] **Step 1: Agregar los errores al bloque `var ( ... )` de errores del dominio**

En `internal/domain/errors.go`, dentro del bloque `var (` existente, agregar después de `ErrInvalidInput`:

```go
	// 404 — Recurso de convivencia no encontrado
	ErrEstudianteNotFound = &AppError{Code: "ESTUDIANTE_NOT_FOUND", Message: "estudiante not found", Status: http.StatusNotFound}

	// 400 — RUT chileno inválido (módulo 11)
	ErrRutInvalido = &AppError{Code: "RUT_INVALIDO", Message: "rut chileno inválido", Status: http.StatusBadRequest}
```

- [ ] **Step 2: Compilar para verificar que no rompe nada**

Run: `go build ./internal/domain/...`
Expected: sin salida (éxito).

- [ ] **Step 3: Commit**

```bash
git add internal/domain/errors.go
git commit -m "feat(domain): errores tipados ErrEstudianteNotFound y ErrRutInvalido"
```

---

## Task 2: Entidad de dominio `Estudiante` + validación RUT (TDD)

**Files:**
- Create: `internal/domain/estudiante.go`
- Test: `internal/domain/estudiante_test.go`

- [ ] **Step 1: Escribir el test que falla**

Crear `internal/domain/estudiante_test.go`:

```go
package domain_test

import (
	"testing"

	"github.com/MargonDiego/GOAPI/internal/domain"
	"github.com/stretchr/testify/assert"
)

func TestValidarRut(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		input      string
		wantNorm   string
		wantErr    bool
	}{
		{"válido con puntos y guion", "12.345.678-5", "12345678-5", false},
		{"válido sin formato", "123456785", "12345678-5", false},
		{"válido DV K", "20.347.878-K", "20347878-K", false},
		{"válido DV k minúscula", "20347878k", "20347878-K", false},
		{"DV incorrecto", "12.345.678-9", "", true},
		{"cuerpo no numérico", "12A45678-5", "", true},
		{"vacío", "", "", true},
		{"solo DV", "5", "", true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			norm, err := domain.ValidarRut(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorIs(t, err, domain.ErrRutInvalido)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantNorm, norm)
			}
		})
	}
}

func TestNewEstudiante(t *testing.T) {
	t.Parallel()
	t.Run("crea con datos válidos", func(t *testing.T) {
		t.Parallel()
		e, err := domain.NewEstudiante("Juan Pérez", "8°B", "colegio-x")
		assert.NoError(t, err)
		assert.Equal(t, "Juan Pérez", e.Nombre)
		assert.Equal(t, "8°B", e.Curso)
		assert.Equal(t, "colegio-x", e.Scope)
	})
	t.Run("rechaza nombre vacío", func(t *testing.T) {
		t.Parallel()
		_, err := domain.NewEstudiante("  ", "8°B", "colegio-x")
		assert.ErrorIs(t, err, domain.ErrInvalidInput)
	})
	t.Run("rechaza curso vacío", func(t *testing.T) {
		t.Parallel()
		_, err := domain.NewEstudiante("Juan", "", "colegio-x")
		assert.ErrorIs(t, err, domain.ErrInvalidInput)
	})
}
```

- [ ] **Step 2: Correr el test para verificar que falla**

Run: `go test ./internal/domain/ -run 'TestValidarRut|TestNewEstudiante' -v`
Expected: FAIL — `undefined: domain.ValidarRut`, `undefined: domain.NewEstudiante`.

- [ ] **Step 3: Implementar la entidad y la validación mínima**

Crear `internal/domain/estudiante.go`:

```go
package domain

import (
	"strconv"
	"strings"
)

// Estudiante es solo un dato del dominio de convivencia: NUNCA es un usuario
// (no autentica, no tiene login). Los campos Nombre y Rut son transitorios
// (texto plano en memoria); su cifrado/hash lo realiza la capa de aplicación
// antes de persistir, igual que el email de User.
type Estudiante struct {
	ID              uint
	Rut             string // transitorio: RUT normalizado en claro (no se persiste así)
	RutHash         string // HMAC-SHA256 — índice único, búsqueda
	RutEncrypted    string // AES-256-GCM — solo display
	Nombre          string // transitorio: nombre en claro
	NombreEncrypted string // AES-256-GCM — solo display
	Curso           string
	Scope           string
}

// NewEstudiante es la factory del dominio. Valida invariantes de creación.
// El RUT se valida y normaliza por separado vía ValidarRut en la capa de aplicación.
func NewEstudiante(nombre, curso, scope string) (*Estudiante, error) {
	nombre = strings.TrimSpace(nombre)
	curso = strings.TrimSpace(curso)
	if nombre == "" {
		return nil, ErrInvalidInput
	}
	if curso == "" {
		return nil, ErrInvalidInput
	}
	return &Estudiante{Nombre: nombre, Curso: curso, Scope: scope}, nil
}

// ValidarRut valida un RUT chileno con el algoritmo de módulo 11 y retorna
// el RUT normalizado en formato "cuerpo-DV" (DV en mayúscula).
// Retorna ErrRutInvalido si el formato o el dígito verificador son incorrectos.
func ValidarRut(rut string) (string, error) {
	var b strings.Builder
	for _, c := range strings.ToUpper(strings.TrimSpace(rut)) {
		if c != '.' && c != '-' && c != ' ' {
			b.WriteRune(c)
		}
	}
	clean := b.String()
	if len(clean) < 2 {
		return "", ErrRutInvalido
	}

	cuerpo := clean[:len(clean)-1]
	dv := clean[len(clean)-1:]

	for _, c := range cuerpo {
		if c < '0' || c > '9' {
			return "", ErrRutInvalido
		}
	}

	suma := 0
	factor := 2
	for i := len(cuerpo) - 1; i >= 0; i-- {
		suma += int(cuerpo[i]-'0') * factor
		factor++
		if factor > 7 {
			factor = 2
		}
	}

	resto := 11 - (suma % 11)
	var dvEsperado string
	switch resto {
	case 11:
		dvEsperado = "0"
	case 10:
		dvEsperado = "K"
	default:
		dvEsperado = strconv.Itoa(resto)
	}

	if dv != dvEsperado {
		return "", ErrRutInvalido
	}
	return cuerpo + "-" + dvEsperado, nil
}
```

- [ ] **Step 4: Correr el test para verificar que pasa**

Run: `go test ./internal/domain/ -run 'TestValidarRut|TestNewEstudiante' -v`
Expected: PASS (todos los subtests).

- [ ] **Step 5: Commit**

```bash
git add internal/domain/estudiante.go internal/domain/estudiante_test.go
git commit -m "feat(domain): entidad Estudiante y validacion RUT modulo 11"
```

---

## Task 3: Puerto `EstudianteRepository`

**Files:**
- Create: `internal/domain/estudiante_repo.go`

- [ ] **Step 1: Crear la interfaz segregada**

Crear `internal/domain/estudiante_repo.go`:

```go
package domain

import "context"

// EstudianteReader agrupa las operaciones de consulta sobre estudiantes.
type EstudianteReader interface {
	FindByID(ctx context.Context, id uint) (*Estudiante, error)
	FindByRutHash(ctx context.Context, rutHash string) (*Estudiante, error)
	Search(ctx context.Context, curso, scope string, page, size int) ([]Estudiante, error)
	CountSearch(ctx context.Context, curso, scope string) (int64, error)
}

// EstudianteWriter agrupa las operaciones de mutación sobre estudiantes.
type EstudianteWriter interface {
	Create(ctx context.Context, e *Estudiante) error
	UpdateDatos(ctx context.Context, e *Estudiante) error
	Delete(ctx context.Context, id uint) error
	Restore(ctx context.Context, id uint) error
}

// EstudianteRepository es la interfaz compuesta (puerto de persistencia).
type EstudianteRepository interface {
	EstudianteReader
	EstudianteWriter
}
```

- [ ] **Step 2: Compilar**

Run: `go build ./internal/domain/...`
Expected: sin salida (éxito).

- [ ] **Step 3: Commit**

```bash
git add internal/domain/estudiante_repo.go
git commit -m "feat(domain): puerto EstudianteRepository segregado"
```

---

## Task 4: Métodos genéricos del `Encryptor` (TDD)

**Files:**
- Modify: `internal/infrastructure/crypto/encryptor.go`
- Test: `internal/infrastructure/crypto/encryptor_test.go`

- [ ] **Step 1: Escribir el test que falla**

Crear `internal/infrastructure/crypto/encryptor_test.go`:

```go
package crypto_test

import (
	"testing"

	appcrypto "github.com/MargonDiego/GOAPI/internal/infrastructure/crypto"
	"github.com/stretchr/testify/assert"
)

func newEnc(t *testing.T) *appcrypto.Encryptor {
	t.Helper()
	enc, err := appcrypto.NewEncryptor([]byte("12345678901234567890123456789012"))
	assert.NoError(t, err)
	return enc
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	t.Parallel()
	enc := newEnc(t)
	plain := "12345678-5"
	ct, err := enc.Encrypt(plain)
	assert.NoError(t, err)
	assert.NotEqual(t, plain, ct)
	got, err := enc.Decrypt(ct)
	assert.NoError(t, err)
	assert.Equal(t, plain, got)
}

func TestEncryptIsNonDeterministic(t *testing.T) {
	t.Parallel()
	enc := newEnc(t)
	a, _ := enc.Encrypt("nombre")
	b, _ := enc.Encrypt("nombre")
	assert.NotEqual(t, a, b)
}

func TestHashIsDeterministic(t *testing.T) {
	t.Parallel()
	enc := newEnc(t)
	assert.Equal(t, enc.Hash("12345678-5"), enc.Hash("12345678-5"))
	assert.NotEqual(t, enc.Hash("a"), enc.Hash("b"))
}

func TestEmailMethodsStillWork(t *testing.T) {
	t.Parallel()
	enc := newEnc(t)
	ct, err := enc.EncryptEmail("user@example.com")
	assert.NoError(t, err)
	got, err := enc.DecryptEmail(ct)
	assert.NoError(t, err)
	assert.Equal(t, "user@example.com", got)
	assert.NotEmpty(t, enc.HashEmail("user@example.com"))
}
```

- [ ] **Step 2: Correr el test para verificar que falla**

Run: `go test ./internal/infrastructure/crypto/ -v`
Expected: FAIL — `enc.Encrypt undefined`, `enc.Decrypt undefined`, `enc.Hash undefined`.

- [ ] **Step 3: Implementar los métodos genéricos y delegar los de email**

En `internal/infrastructure/crypto/encryptor.go`, agregar los tres métodos genéricos (al final del archivo, antes del fin) y refactorizar los de email para delegar:

```go
// Encrypt cifra cualquier string con AES-256-GCM y nonce aleatorio.
// Resultado: base64(nonce || ciphertext || tag). No determinista.
func (e *Encryptor) Encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", fmt.Errorf("aes cipher init: %w", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("aes-gcm init: %w", err)
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce generation: %w", err)
	}
	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt descifra un valor producido por Encrypt.
func (e *Encryptor) Decrypt(encrypted string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", fmt.Errorf("aes cipher init: %w", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("aes-gcm init: %w", err)
	}
	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", errors.New("decryption failed: invalid ciphertext or tampered data")
	}
	return string(plaintext), nil
}

// Hash genera un HMAC-SHA256 determinista de cualquier valor.
func (e *Encryptor) Hash(value string) string {
	mac := hmac.New(sha256.New, e.key)
	mac.Write([]byte(value))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
```

Luego reemplazar los cuerpos de los métodos de email para delegar (DRY):

```go
// EncryptEmail cifra el email. Delega en Encrypt (mantiene la API existente).
func (e *Encryptor) EncryptEmail(email string) (string, error) {
	return e.Encrypt(email)
}

// DecryptEmail descifra el email. Delega en Decrypt.
func (e *Encryptor) DecryptEmail(encrypted string) (string, error) {
	return e.Decrypt(encrypted)
}

// HashEmail genera el HMAC-SHA256 del email. Delega en Hash.
func (e *Encryptor) HashEmail(email string) string {
	return e.Hash(email)
}
```

- [ ] **Step 4: Correr los tests del encryptor**

Run: `go test ./internal/infrastructure/crypto/ -v`
Expected: PASS (incluido `TestEmailMethodsStillWork`).

- [ ] **Step 5: Correr la suite de aplicación para confirmar que el refactor de email no rompió nada**

Run: `go test ./internal/application/...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/infrastructure/crypto/encryptor.go internal/infrastructure/crypto/encryptor_test.go
git commit -m "feat(crypto): metodos genericos Encrypt/Decrypt/Hash; email delega en ellos"
```

---

## Task 5: `EstudianteService` (TDD con mocks)

**Files:**
- Create: `internal/application/estudiante_service.go`
- Test: `internal/application/estudiante_service_test.go`
- Modify: `.mockery.yaml`
- Generate: `mocks/mock_EstudianteRepository.go`

- [ ] **Step 1: Registrar la interfaz en `.mockery.yaml`**

Abrir `.mockery.yaml`. Localizar el bloque donde se declara `UserRepository` bajo el paquete `github.com/MargonDiego/GOAPI/internal/domain` y agregar una entrada `EstudianteRepository` replicando exactamente el mismo formato/indentación que `UserRepository` (mismo paquete `internal/domain`, misma sección `interfaces:`).

- [ ] **Step 2: Generar el mock**

Run: `go generate ./...`
Expected: se crea `mocks/mock_EstudianteRepository.go` (verificar con `git status`).

- [ ] **Step 3: Escribir el test de servicio que falla**

Crear `internal/application/estudiante_service_test.go`:

```go
package application_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/MargonDiego/GOAPI/internal/application"
	"github.com/MargonDiego/GOAPI/internal/domain"
	appcrypto "github.com/MargonDiego/GOAPI/internal/infrastructure/crypto"
	"github.com/MargonDiego/GOAPI/mocks"
)

func encForEstudiante(t *testing.T) *appcrypto.Encryptor {
	t.Helper()
	enc, err := appcrypto.NewEncryptor([]byte("12345678901234567890123456789012"))
	assert.NoError(t, err)
	return enc
}

func TestEstudianteService_Create(t *testing.T) {
	t.Parallel()

	t.Run("crea estudiante con RUT válido", func(t *testing.T) {
		t.Parallel()
		repo := mocks.NewMockEstudianteRepository(t)
		repo.On("FindByRutHash", mock.Anything, mock.Anything).Return(nil, domain.ErrEstudianteNotFound)
		repo.On("Create", mock.Anything, mock.AnythingOfType("*domain.Estudiante")).Return(nil)

		svc := application.NewEstudianteService(repo, encForEstudiante(t), nil)
		ctx := application.WithScope(context.Background(), "colegio-x")

		err := svc.Create(ctx, "12.345.678-5", "Juan Pérez", "8°B")
		assert.NoError(t, err)
	})

	t.Run("rechaza RUT inválido", func(t *testing.T) {
		t.Parallel()
		repo := mocks.NewMockEstudianteRepository(t)
		svc := application.NewEstudianteService(repo, encForEstudiante(t), nil)
		ctx := application.WithScope(context.Background(), "colegio-x")

		err := svc.Create(ctx, "12.345.678-9", "Juan", "8°B")
		assert.ErrorIs(t, err, domain.ErrRutInvalido)
	})

	t.Run("rechaza RUT duplicado", func(t *testing.T) {
		t.Parallel()
		repo := mocks.NewMockEstudianteRepository(t)
		repo.On("FindByRutHash", mock.Anything, mock.Anything).
			Return(&domain.Estudiante{ID: 1}, nil)

		svc := application.NewEstudianteService(repo, encForEstudiante(t), nil)
		ctx := application.WithScope(context.Background(), "colegio-x")

		err := svc.Create(ctx, "12.345.678-5", "Juan", "8°B")
		assert.ErrorIs(t, err, domain.ErrInvalidInput)
	})
}

func TestEstudianteService_GetByID(t *testing.T) {
	t.Parallel()
	enc := encForEstudiante(t)
	rutCt, _ := enc.Encrypt("12345678-5")
	nomCt, _ := enc.Encrypt("Juan Pérez")

	repo := mocks.NewMockEstudianteRepository(t)
	repo.On("FindByID", mock.Anything, uint(1)).Return(&domain.Estudiante{
		ID: 1, RutEncrypted: rutCt, NombreEncrypted: nomCt, Curso: "8°B", Scope: "colegio-x",
	}, nil)

	svc := application.NewEstudianteService(repo, enc, nil)
	ctx := application.WithScope(context.Background(), "colegio-x")

	data, err := svc.GetByID(ctx, 1)
	assert.NoError(t, err)
	assert.Equal(t, "12345678-5", data.Rut)
	assert.Equal(t, "Juan Pérez", data.Nombre)
	assert.Equal(t, "8°B", data.Curso)
}
```

- [ ] **Step 4: Correr el test para verificar que falla**

Run: `go test ./internal/application/ -run TestEstudianteService -v`
Expected: FAIL — `undefined: application.NewEstudianteService`.

- [ ] **Step 5: Implementar el servicio**

Crear `internal/application/estudiante_service.go`:

```go
package application

import (
	"context"
	"errors"
	"fmt"

	"github.com/MargonDiego/GOAPI/internal/domain"
	appcrypto "github.com/MargonDiego/GOAPI/internal/infrastructure/crypto"
)

// EstudianteData es la vista descifrada del estudiante para respuestas autorizadas.
// El descifrado ocurre SIEMPRE en esta capa (nunca en presentación).
type EstudianteData struct {
	ID     uint
	Rut    string
	Nombre string
	Curso  string
	Scope  string
}

type EstudianteService interface {
	Create(ctx context.Context, rut, nombre, curso string) error
	GetByID(ctx context.Context, id uint) (EstudianteData, error)
	Search(ctx context.Context, curso string, page, size int) (domain.PaginatedResult[EstudianteData], error)
	UpdateDatos(ctx context.Context, id uint, nombre, curso string) error
	Delete(ctx context.Context, id uint) error
	Restore(ctx context.Context, id uint) error
}

type estudianteService struct {
	repo  domain.EstudianteRepository
	enc   *appcrypto.Encryptor
	audit auditService
}

// NewEstudianteService construye el servicio. auditRepo puede ser nil
// (la auditoría se ignora silenciosamente, igual que UserService).
func NewEstudianteService(repo domain.EstudianteRepository, enc *appcrypto.Encryptor, auditRepo domain.AuditRepository) EstudianteService {
	return &estudianteService{repo: repo, enc: enc, audit: newAuditService(auditRepo)}
}

func (s *estudianteService) Create(ctx context.Context, rut, nombre, curso string) error {
	norm, err := domain.ValidarRut(rut)
	if err != nil {
		return err
	}

	rutHash := s.enc.Hash(norm)
	_, err = s.repo.FindByRutHash(ctx, rutHash)
	if err == nil {
		return fmt.Errorf("%w: rut already exists", domain.ErrInvalidInput)
	}
	if !errors.Is(err, domain.ErrEstudianteNotFound) {
		return fmt.Errorf("failed to check rut: %w", err)
	}

	scope, _ := ScopeFromContext(ctx)
	e, err := domain.NewEstudiante(nombre, curso, scope)
	if err != nil {
		return fmt.Errorf("failed to create estudiante: %w", err)
	}

	rutCt, err := s.enc.Encrypt(norm)
	if err != nil {
		return fmt.Errorf("failed to encrypt rut: %w", err)
	}
	nomCt, err := s.enc.Encrypt(e.Nombre)
	if err != nil {
		return fmt.Errorf("failed to encrypt nombre: %w", err)
	}
	e.RutEncrypted = rutCt
	e.RutHash = rutHash
	e.NombreEncrypted = nomCt

	if err := s.repo.Create(ctx, e); err != nil {
		return fmt.Errorf("failed to create estudiante: %w", err)
	}

	s.audit.log(ctx, "create_estudiante", "estudiante", e.ID, nil, map[string]any{"curso": curso})
	return nil
}

func (s *estudianteService) GetByID(ctx context.Context, id uint) (EstudianteData, error) {
	e, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return EstudianteData{}, fmt.Errorf("failed to get estudiante: %w", err)
	}
	if err := assertScopeAccess(ctx, e.Scope); err != nil {
		return EstudianteData{}, err
	}
	// Auditoría de acceso (Ley 21.719): registra la LECTURA de datos del menor.
	s.audit.log(ctx, "read_estudiante", "estudiante", e.ID, nil, nil)
	return s.decrypt(e)
}

func (s *estudianteService) Search(ctx context.Context, curso string, page, size int) (domain.PaginatedResult[EstudianteData], error) {
	if page < 1 {
		page = 1
	}
	if size <= 0 || size > 100 {
		size = 10
	}
	scope, _ := ScopeFromContext(ctx)

	list, err := s.repo.Search(ctx, curso, scope, page, size)
	if err != nil {
		return domain.PaginatedResult[EstudianteData]{}, fmt.Errorf("failed to search estudiantes: %w", err)
	}
	total, err := s.repo.CountSearch(ctx, curso, scope)
	if err != nil {
		return domain.PaginatedResult[EstudianteData]{}, fmt.Errorf("failed to count estudiantes: %w", err)
	}

	data := make([]EstudianteData, 0, len(list))
	for i := range list {
		d, err := s.decrypt(&list[i])
		if err != nil {
			return domain.PaginatedResult[EstudianteData]{}, err
		}
		data = append(data, d)
	}
	return domain.NewPaginatedResult(data, page, size, int(total)), nil
}

func (s *estudianteService) UpdateDatos(ctx context.Context, id uint, nombre, curso string) error {
	e, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to find estudiante: %w", err)
	}
	if err := assertScopeAccess(ctx, e.Scope); err != nil {
		return err
	}
	if nombre != "" {
		nomCt, err := s.enc.Encrypt(nombre)
		if err != nil {
			return fmt.Errorf("failed to encrypt nombre: %w", err)
		}
		e.NombreEncrypted = nomCt
	}
	if curso != "" {
		e.Curso = curso
	}
	if err := s.repo.UpdateDatos(ctx, e); err != nil {
		return fmt.Errorf("failed to update estudiante: %w", err)
	}
	s.audit.log(ctx, "update_estudiante", "estudiante", e.ID, nil, map[string]any{"curso": curso})
	return nil
}

func (s *estudianteService) Delete(ctx context.Context, id uint) error {
	e, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to find estudiante: %w", err)
	}
	if err := assertScopeAccess(ctx, e.Scope); err != nil {
		return err
	}
	if err := s.repo.Delete(ctx, id); err != nil {
		return fmt.Errorf("failed to delete estudiante: %w", err)
	}
	s.audit.log(ctx, "delete_estudiante", "estudiante", id, nil, nil)
	return nil
}

func (s *estudianteService) Restore(ctx context.Context, id uint) error {
	if err := s.repo.Restore(ctx, id); err != nil {
		return fmt.Errorf("failed to restore estudiante: %w", err)
	}
	s.audit.log(ctx, "restore_estudiante", "estudiante", id, nil, nil)
	return nil
}

func (s *estudianteService) decrypt(e *domain.Estudiante) (EstudianteData, error) {
	rut, err := s.enc.Decrypt(e.RutEncrypted)
	if err != nil {
		return EstudianteData{}, fmt.Errorf("failed to decrypt rut: %w", err)
	}
	nombre, err := s.enc.Decrypt(e.NombreEncrypted)
	if err != nil {
		return EstudianteData{}, fmt.Errorf("failed to decrypt nombre: %w", err)
	}
	return EstudianteData{ID: e.ID, Rut: rut, Nombre: nombre, Curso: e.Curso, Scope: e.Scope}, nil
}
```

> Nota: `auditService`, `newAuditService`, `ScopeFromContext`, `assertScopeAccess` y `WithScope` ya existen en el paquete `application` (ver `audit_helper.go`, `audit_context.go`, `user_service.go`). No se redefinen.

- [ ] **Step 6: Correr el test para verificar que pasa**

Run: `go test ./internal/application/ -run TestEstudianteService -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add .mockery.yaml mocks/mock_EstudianteRepository.go internal/application/estudiante_service.go internal/application/estudiante_service_test.go
git commit -m "feat(application): EstudianteService con cifrado PII, scope y auditoria de acceso"
```

---

## Task 6: Modelo GORM + mappers

**Files:**
- Create: `internal/infrastructure/persistence/convivencia_models.go`

- [ ] **Step 1: Crear el modelo y los mappers**

Crear `internal/infrastructure/persistence/convivencia_models.go`:

```go
package persistence

import (
	"github.com/MargonDiego/GOAPI/internal/domain"
	"gorm.io/gorm"
)

// Estudiante es el modelo de persistencia (separado de la entidad de dominio).
type Estudiante struct {
	gorm.Model
	RutHash         string `gorm:"column:rut_hash;uniqueIndex;not null"`
	RutEncrypted    string `gorm:"column:rut_encrypted;not null"`
	NombreEncrypted string `gorm:"column:nombre_encrypted;not null"`
	Curso           string `gorm:"column:curso;index;not null"`
	Scope           string `gorm:"column:scope;index;not null;default:''"`
}

func (Estudiante) TableName() string { return "estudiantes" }

func toDomainEstudiante(e *Estudiante) *domain.Estudiante {
	if e == nil {
		return nil
	}
	return &domain.Estudiante{
		ID:              e.ID,
		RutHash:         e.RutHash,
		RutEncrypted:    e.RutEncrypted,
		NombreEncrypted: e.NombreEncrypted,
		Curso:           e.Curso,
		Scope:           e.Scope,
	}
}

func toDBEstudiante(d *domain.Estudiante) *Estudiante {
	if d == nil {
		return nil
	}
	e := &Estudiante{
		RutHash:         d.RutHash,
		RutEncrypted:    d.RutEncrypted,
		NombreEncrypted: d.NombreEncrypted,
		Curso:           d.Curso,
		Scope:           d.Scope,
	}
	if d.ID != 0 {
		e.ID = d.ID
	}
	return e
}
```

- [ ] **Step 2: Compilar**

Run: `go build ./internal/infrastructure/persistence/...`
Expected: sin salida (éxito).

- [ ] **Step 3: Commit**

```bash
git add internal/infrastructure/persistence/convivencia_models.go
git commit -m "feat(persistence): modelo GORM Estudiante y mappers"
```

---

## Task 7: Migración SQL

**Files:**
- Create: `migrations/000009_create_estudiantes.up.sql`
- Create: `migrations/000009_create_estudiantes.down.sql`

- [ ] **Step 1: Crear la migración up**

Crear `migrations/000009_create_estudiantes.up.sql`:

```sql
-- Tabla de estudiantes (solo dato, nunca usuario).
-- PII cifrada a nivel de aplicación: rut_encrypted/nombre_encrypted (AES-256-GCM),
-- rut_hash (HMAC-SHA256) como índice único para búsqueda/unicidad sin exponer el RUT.

CREATE TABLE IF NOT EXISTS estudiantes (
    id               BIGSERIAL PRIMARY KEY,
    created_at       TIMESTAMPTZ,
    updated_at       TIMESTAMPTZ,
    deleted_at       TIMESTAMPTZ,
    rut_hash         VARCHAR(64) NOT NULL,
    rut_encrypted    TEXT        NOT NULL,
    nombre_encrypted TEXT        NOT NULL,
    curso            VARCHAR(50) NOT NULL,
    scope            VARCHAR(100) NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_estudiantes_rut_hash
    ON estudiantes (rut_hash) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_estudiantes_curso ON estudiantes (curso);
CREATE INDEX IF NOT EXISTS idx_estudiantes_scope ON estudiantes (scope);
CREATE INDEX IF NOT EXISTS idx_estudiantes_deleted_at ON estudiantes (deleted_at);
```

- [ ] **Step 2: Crear la migración down**

Crear `migrations/000009_create_estudiantes.down.sql`:

```sql
DROP TABLE IF EXISTS estudiantes;
```

- [ ] **Step 3: Verificar que la migración aplica (requiere Postgres local del proyecto)**

Run: `go run ./cmd/api` y detener tras el log de arranque (Ctrl+C), o correr el test de integración de la Task 8.
Expected: arranque sin error de migración (`migrate.ErrNoChange` o aplicación exitosa).

- [ ] **Step 4: Commit**

```bash
git add migrations/000009_create_estudiantes.up.sql migrations/000009_create_estudiantes.down.sql
git commit -m "feat(migrations): tabla estudiantes con indices y soft delete"
```

---

## Task 8: Implementación GORM del repositorio (TDD integración)

**Files:**
- Create: `internal/infrastructure/persistence/estudiante_repository.go`
- Test: `internal/infrastructure/persistence/estudiante_repository_integration_test.go`

- [ ] **Step 1: Escribir el test de integración que falla**

Abrir `internal/infrastructure/persistence/repository_integration_test.go` y reutilizar su helper de conexión (p. ej. `setupTestDB(t)` o equivalente). Crear `internal/infrastructure/persistence/estudiante_repository_integration_test.go` siguiendo el MISMO mecanismo de setup que ese archivo:

```go
package persistence_test

import (
	"context"
	"testing"

	"github.com/MargonDiego/GOAPI/internal/domain"
	"github.com/MargonDiego/GOAPI/internal/infrastructure/persistence"
	"github.com/stretchr/testify/assert"
)

func TestEstudianteRepository_CreateAndFind(t *testing.T) {
	db := setupTestDB(t) // helper existente en repository_integration_test.go
	repo := persistence.NewEstudianteRepository(db)
	ctx := context.Background()

	e := &domain.Estudiante{
		RutHash:         "hash-abc",
		RutEncrypted:    "enc-rut",
		NombreEncrypted: "enc-nombre",
		Curso:           "8°B",
		Scope:           "colegio-x",
	}
	assert.NoError(t, repo.Create(ctx, e))
	assert.NotZero(t, e.ID)

	got, err := repo.FindByID(ctx, e.ID)
	assert.NoError(t, err)
	assert.Equal(t, "hash-abc", got.RutHash)

	byHash, err := repo.FindByRutHash(ctx, "hash-abc")
	assert.NoError(t, err)
	assert.Equal(t, e.ID, byHash.ID)

	_, err = repo.FindByRutHash(ctx, "no-existe")
	assert.ErrorIs(t, err, domain.ErrEstudianteNotFound)

	assert.NoError(t, repo.Delete(ctx, e.ID))
	_, err = repo.FindByID(ctx, e.ID)
	assert.ErrorIs(t, err, domain.ErrEstudianteNotFound)

	assert.NoError(t, repo.Restore(ctx, e.ID))
	_, err = repo.FindByID(ctx, e.ID)
	assert.NoError(t, err)
}
```

> Si el helper de setup tiene otro nombre en `repository_integration_test.go`, usar el nombre real de ese archivo. NO crear un helper nuevo.

- [ ] **Step 2: Correr el test para verificar que falla**

Run: `go test ./internal/infrastructure/persistence/ -run TestEstudianteRepository -v`
Expected: FAIL — `undefined: persistence.NewEstudianteRepository`.

- [ ] **Step 3: Implementar el repositorio**

Crear `internal/infrastructure/persistence/estudiante_repository.go`:

```go
package persistence

import (
	"context"
	"errors"
	"fmt"

	"github.com/MargonDiego/GOAPI/internal/domain"
	"gorm.io/gorm"
)

type estudianteRepository struct {
	db *gorm.DB
}

func NewEstudianteRepository(db *gorm.DB) domain.EstudianteRepository {
	return &estudianteRepository{db: db}
}

func (r *estudianteRepository) Create(ctx context.Context, e *domain.Estudiante) error {
	dbE := toDBEstudiante(e)
	if err := r.db.WithContext(ctx).Create(dbE).Error; err != nil {
		return fmt.Errorf("repository unable to create estudiante: %w", err)
	}
	e.ID = dbE.ID
	return nil
}

func (r *estudianteRepository) UpdateDatos(ctx context.Context, e *domain.Estudiante) error {
	dbE := toDBEstudiante(e)
	if err := r.db.WithContext(ctx).
		Model(&Estudiante{}).Where("id = ?", e.ID).
		Select("nombre_encrypted", "curso").
		Updates(map[string]any{
			"nombre_encrypted": dbE.NombreEncrypted,
			"curso":            dbE.Curso,
		}).Error; err != nil {
		return fmt.Errorf("repository unable to update estudiante: %w", err)
	}
	return nil
}

func (r *estudianteRepository) FindByID(ctx context.Context, id uint) (*domain.Estudiante, error) {
	var e Estudiante
	if err := r.db.WithContext(ctx).First(&e, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrEstudianteNotFound
		}
		return nil, fmt.Errorf("database query error: %w", err)
	}
	return toDomainEstudiante(&e), nil
}

func (r *estudianteRepository) FindByRutHash(ctx context.Context, rutHash string) (*domain.Estudiante, error) {
	var e Estudiante
	if err := r.db.WithContext(ctx).Where("rut_hash = ?", rutHash).First(&e).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrEstudianteNotFound
		}
		return nil, fmt.Errorf("database query error: %w", err)
	}
	return toDomainEstudiante(&e), nil
}

func (r *estudianteRepository) Search(ctx context.Context, curso, scope string, page, size int) ([]domain.Estudiante, error) {
	var rows []Estudiante
	db := r.db.WithContext(ctx).Where("scope = ? OR scope = ''", scope)
	if curso != "" {
		db = db.Where("curso = ?", curso)
	}
	offset := (page - 1) * size
	if err := db.Offset(offset).Limit(size).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("database search estudiantes error: %w", err)
	}
	out := make([]domain.Estudiante, 0, len(rows))
	for i := range rows {
		out = append(out, *toDomainEstudiante(&rows[i]))
	}
	return out, nil
}

func (r *estudianteRepository) CountSearch(ctx context.Context, curso, scope string) (int64, error) {
	var count int64
	db := r.db.WithContext(ctx).Model(&Estudiante{}).Where("scope = ? OR scope = ''", scope)
	if curso != "" {
		db = db.Where("curso = ?", curso)
	}
	if err := db.Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

func (r *estudianteRepository) Delete(ctx context.Context, id uint) error {
	result := r.db.WithContext(ctx).Delete(&Estudiante{}, id)
	if result.Error != nil {
		return fmt.Errorf("repository unable to delete estudiante: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return domain.ErrEstudianteNotFound
	}
	return nil
}

func (r *estudianteRepository) Restore(ctx context.Context, id uint) error {
	result := r.db.WithContext(ctx).Unscoped().Model(&Estudiante{}).
		Where("id = ?", id).Update("deleted_at", nil)
	if result.Error != nil {
		return fmt.Errorf("repository unable to restore estudiante: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return domain.ErrEstudianteNotFound
	}
	return nil
}
```

- [ ] **Step 4: Correr el test de integración**

Run: `go test ./internal/infrastructure/persistence/ -run TestEstudianteRepository -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/infrastructure/persistence/estudiante_repository.go internal/infrastructure/persistence/estudiante_repository_integration_test.go
git commit -m "feat(persistence): repositorio GORM de Estudiante con soft delete"
```

---

## Task 9: Seed de permisos RBAC

**Files:**
- Modify: `internal/infrastructure/persistence/postgres.go` (función `seedDefaults`)

- [ ] **Step 1: Agregar los permisos al seed**

En `internal/infrastructure/persistence/postgres.go`, dentro de `seedDefaults`, después de `manageUsersPerm` y antes de la línea `db.Model(&adminRole).Association("Permissions").Append(...)`, agregar:

```go
	readEstudiantesPerm := Permission{Name: "read:estudiantes"}
	db.FirstOrCreate(&readEstudiantesPerm, Permission{Name: "read:estudiantes"})

	manageEstudiantesPerm := Permission{Name: "manage:estudiantes"}
	db.FirstOrCreate(&manageEstudiantesPerm, Permission{Name: "manage:estudiantes"})
```

Y modificar la línea de asociación del `adminRole` para incluir los nuevos permisos:

```go
	db.Model(&adminRole).Association("Permissions").Append(&readPerm, &writePerm, &manageRolesPerm, &manageUsersPerm, &readEstudiantesPerm, &manageEstudiantesPerm)
```

- [ ] **Step 2: Compilar**

Run: `go build ./...`
Expected: sin salida (éxito).

- [ ] **Step 3: Commit**

```bash
git add internal/infrastructure/persistence/postgres.go
git commit -m "feat(persistence): seed permisos read:estudiantes y manage:estudiantes"
```

---

## Task 10: Handler HTTP + DTOs (TDD httptest)

**Files:**
- Create: `internal/presentation/rest/handlers/estudiante_handler.go`
- Test: `internal/presentation/rest/handlers/estudiante_handler_test.go`

- [ ] **Step 1: Escribir el test de handler que falla**

Abrir `internal/presentation/rest/handlers/user_handler_test.go` para copiar el mecanismo exacto de construcción de request/response y mock de servicio. Crear `internal/presentation/rest/handlers/estudiante_handler_test.go`:

```go
package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MargonDiego/GOAPI/internal/application"
	"github.com/MargonDiego/GOAPI/internal/domain"
	"github.com/MargonDiego/GOAPI/internal/presentation/rest/handlers"
	"github.com/stretchr/testify/assert"
)

// fakeEstudianteService implementa application.EstudianteService para tests de handler.
type fakeEstudianteService struct {
	createErr error
	getData   application.EstudianteData
	getErr    error
}

func (f *fakeEstudianteService) Create(ctx context.Context, rut, nombre, curso string) error {
	return f.createErr
}
func (f *fakeEstudianteService) GetByID(ctx context.Context, id uint) (application.EstudianteData, error) {
	return f.getData, f.getErr
}
func (f *fakeEstudianteService) Search(ctx context.Context, curso string, page, size int) (domain.PaginatedResult[application.EstudianteData], error) {
	return domain.PaginatedResult[application.EstudianteData]{}, nil
}
func (f *fakeEstudianteService) UpdateDatos(ctx context.Context, id uint, nombre, curso string) error {
	return nil
}
func (f *fakeEstudianteService) Delete(ctx context.Context, id uint) error  { return nil }
func (f *fakeEstudianteService) Restore(ctx context.Context, id uint) error { return nil }

func TestEstudianteHandler_Create(t *testing.T) {
	t.Parallel()
	h := handlers.NewEstudianteHandler(&fakeEstudianteService{})
	body, _ := json.Marshal(map[string]string{"rut": "12.345.678-5", "nombre": "Juan", "curso": "8°B"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/estudiantes", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.Create(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)
}

func TestEstudianteHandler_Create_RutInvalido(t *testing.T) {
	t.Parallel()
	h := handlers.NewEstudianteHandler(&fakeEstudianteService{createErr: domain.ErrRutInvalido})
	body, _ := json.Marshal(map[string]string{"rut": "12.345.678-9", "nombre": "Juan", "curso": "8°B"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/estudiantes", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.Create(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}
```

- [ ] **Step 2: Correr el test para verificar que falla**

Run: `go test ./internal/presentation/rest/handlers/ -run TestEstudianteHandler -v`
Expected: FAIL — `undefined: handlers.NewEstudianteHandler`.

- [ ] **Step 3: Implementar el handler**

Crear `internal/presentation/rest/handlers/estudiante_handler.go`:

```go
package handlers

import (
	"net/http"

	"github.com/MargonDiego/GOAPI/internal/application"
)

type EstudianteResponse struct {
	ID     uint   `json:"id"`
	Rut    string `json:"rut"`
	Nombre string `json:"nombre"`
	Curso  string `json:"curso"`
}

type CreateEstudianteRequest struct {
	Rut    string `json:"rut" validate:"required" example:"12.345.678-5"`
	Nombre string `json:"nombre" validate:"required,min=2,max=120" example:"Juan Pérez"`
	Curso  string `json:"curso" validate:"required,min=1,max=50" example:"8°B"`
}

type UpdateEstudianteRequest struct {
	Nombre string `json:"nombre,omitempty" validate:"omitempty,min=2,max=120"`
	Curso  string `json:"curso,omitempty" validate:"omitempty,min=1,max=50"`
}

type EstudianteHandler struct {
	svc application.EstudianteService
}

func NewEstudianteHandler(s application.EstudianteService) *EstudianteHandler {
	return &EstudianteHandler{svc: s}
}

// Create crea un estudiante.
//
// @Summary      Crear estudiante
// @Description  Crea un estudiante (solo dato, no usuario). PII cifrada en reposo.
// @Tags         estudiantes
// @Accept       json
// @Produce      json
// @Param        body body CreateEstudianteRequest true "Datos del estudiante"
// @Security     BearerAuth
// @Success      201 {object} MessageResponse
// @Failure      400 {object} ErrorResponse
// @Failure      401 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
// @Failure      409 {object} ErrorResponse
// @Router       /estudiantes [post]
func (h *EstudianteHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req CreateEstudianteRequest
	if errs := DecodeAndValidate(r, &req); len(errs) > 0 {
		RenderValidationError(w, errs)
		return
	}
	if err := h.svc.Create(withActor(r), req.Rut, req.Nombre, req.Curso); err != nil {
		RenderError(w, r, err)
		return
	}
	RespondJSON(w, http.StatusCreated, MessageResponse{Message: "estudiante created successfully"})
}

// GetByID obtiene un estudiante por ID.
//
// @Summary      Obtener estudiante
// @Tags         estudiantes
// @Produce      json
// @Param        id path int true "Estudiante ID"
// @Security     BearerAuth
// @Success      200 {object} EstudianteResponse
// @Failure      400 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
// @Failure      404 {object} ErrorResponse
// @Router       /estudiantes/{id} [get]
func (h *EstudianteHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	id, err := getIDFromURL(r, "id")
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid estudiante id")
		return
	}
	d, err := h.svc.GetByID(withActor(r), uint(id))
	if err != nil {
		RenderError(w, r, err)
		return
	}
	RespondJSON(w, http.StatusOK, EstudianteResponse{ID: d.ID, Rut: d.Rut, Nombre: d.Nombre, Curso: d.Curso})
}

// Search lista estudiantes paginados, filtrables por curso.
//
// @Summary      Listar estudiantes
// @Tags         estudiantes
// @Produce      json
// @Param        page query int false "Página" default(1)
// @Param        size query int false "Tamaño" default(10)
// @Param        curso query string false "Filtrar por curso"
// @Security     BearerAuth
// @Success      200 {object} APIResponse
// @Failure      401 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
// @Router       /estudiantes [get]
func (h *EstudianteHandler) Search(w http.ResponseWriter, r *http.Request) {
	page := parseQueryInt(r, "page", 1)
	size := parseQueryInt(r, "size", 10)
	curso := r.URL.Query().Get("curso")

	result, err := h.svc.Search(withActor(r), curso, page, size)
	if err != nil {
		RenderError(w, r, err)
		return
	}
	resp := make([]EstudianteResponse, 0, len(result.Data))
	for _, d := range result.Data {
		resp = append(resp, EstudianteResponse{ID: d.ID, Rut: d.Rut, Nombre: d.Nombre, Curso: d.Curso})
	}
	RespondPaginated(w, resp, result.Page, result.Size, result.Total)
}

// Update actualiza nombre/curso de un estudiante.
//
// @Summary      Actualizar estudiante
// @Tags         estudiantes
// @Accept       json
// @Produce      json
// @Param        id path int true "Estudiante ID"
// @Param        body body UpdateEstudianteRequest true "Datos a actualizar"
// @Security     BearerAuth
// @Success      200 {object} MessageResponse
// @Failure      400 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
// @Failure      404 {object} ErrorResponse
// @Router       /estudiantes/{id} [put]
func (h *EstudianteHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := getIDFromURL(r, "id")
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid estudiante id")
		return
	}
	var req UpdateEstudianteRequest
	if errs := DecodeAndValidate(r, &req); len(errs) > 0 {
		RenderValidationError(w, errs)
		return
	}
	if req.Nombre == "" && req.Curso == "" {
		RespondError(w, http.StatusBadRequest, "at least one field to update is required")
		return
	}
	if err := h.svc.UpdateDatos(withActor(r), uint(id), req.Nombre, req.Curso); err != nil {
		RenderError(w, r, err)
		return
	}
	RespondJSON(w, http.StatusOK, MessageResponse{Message: "estudiante updated successfully"})
}

// Delete elimina (soft) un estudiante.
//
// @Summary      Eliminar estudiante
// @Tags         estudiantes
// @Produce      json
// @Param        id path int true "Estudiante ID"
// @Security     BearerAuth
// @Success      200 {object} MessageResponse
// @Failure      400 {object} ErrorResponse
// @Failure      403 {object} ErrorResponse
// @Failure      404 {object} ErrorResponse
// @Router       /estudiantes/{id} [delete]
func (h *EstudianteHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := getIDFromURL(r, "id")
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid estudiante id")
		return
	}
	if err := h.svc.Delete(withActor(r), uint(id)); err != nil {
		RenderError(w, r, err)
		return
	}
	RespondJSON(w, http.StatusOK, MessageResponse{Message: "estudiante deleted successfully"})
}

// Restore recupera un estudiante soft-deleted.
//
// @Summary      Restaurar estudiante
// @Tags         estudiantes
// @Produce      json
// @Param        id path int true "Estudiante ID"
// @Security     BearerAuth
// @Success      200 {object} MessageResponse
// @Failure      400 {object} ErrorResponse
// @Failure      404 {object} ErrorResponse
// @Router       /estudiantes/{id}/restore [post]
func (h *EstudianteHandler) Restore(w http.ResponseWriter, r *http.Request) {
	id, err := getIDFromURL(r, "id")
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid estudiante id")
		return
	}
	if err := h.svc.Restore(withActor(r), uint(id)); err != nil {
		RenderError(w, r, err)
		return
	}
	RespondJSON(w, http.StatusOK, MessageResponse{Message: "estudiante restored successfully"})
}
```

- [ ] **Step 4: Correr los tests de handler**

Run: `go test ./internal/presentation/rest/handlers/ -run TestEstudianteHandler -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/presentation/rest/handlers/estudiante_handler.go internal/presentation/rest/handlers/estudiante_handler_test.go
git commit -m "feat(presentation): handler y DTOs de Estudiante"
```

---

## Task 11: Wiring (router + main)

**Files:**
- Modify: `internal/presentation/rest/router.go`
- Modify: `cmd/api/main.go`

- [ ] **Step 1: Agregar el parámetro y las rutas en `NewRouter`**

En `internal/presentation/rest/router.go`, agregar `estudianteHandler *handlers.EstudianteHandler` a la firma de `NewRouter` (después de `roleHandler`). Y agregar el bloque de rutas después del bloque de `rolesRoute`/`permsRoute` (rutas fijas antes de `/{id}`):

```go
	// Rutas de Estudiantes (datos de menores — RBAC + scope)
	estudiantesRoute := api.PathPrefix("/estudiantes").Subrouter()
	estudiantesRoute.Handle("", authMw.RequirePermission("read:estudiantes")(http.HandlerFunc(estudianteHandler.Search))).Methods("GET")
	estudiantesRoute.Handle("", authMw.RequirePermission("manage:estudiantes")(http.HandlerFunc(estudianteHandler.Create))).Methods("POST")
	estudiantesRoute.Handle("/{id}", authMw.RequirePermission("read:estudiantes")(http.HandlerFunc(estudianteHandler.GetByID))).Methods("GET")
	estudiantesRoute.Handle("/{id}", authMw.RequirePermission("manage:estudiantes")(http.HandlerFunc(estudianteHandler.Update))).Methods("PUT")
	estudiantesRoute.Handle("/{id}", authMw.RequirePermission("manage:estudiantes")(http.HandlerFunc(estudianteHandler.Delete))).Methods("DELETE")
	estudiantesRoute.Handle("/{id}/restore", authMw.RequirePermission("manage:estudiantes")(http.HandlerFunc(estudianteHandler.RestoreUser))).Methods("POST")
```

> Corrección: el método del handler es `Restore`, no `RestoreUser`. Usar `estudianteHandler.Restore` en la última línea.

- [ ] **Step 2: Conectar el wiring en `main.go`**

En `cmd/api/main.go`:

1. En `type infraDeps struct`, agregar: `estudianteRepo domain.EstudianteRepository`
2. En `type appServices struct`, agregar: `estudiante application.EstudianteService`
3. En `mustInitInfra`, dentro del `return &infraDeps{...}`, agregar: `estudianteRepo: persistence.NewEstudianteRepository(db),`
4. En `initServices`, dentro del `return &appServices{...}`, agregar: `estudiante: application.NewEstudianteService(infra.estudianteRepo, infra.enc, infra.auditRepo),`
5. En `initServer`, después de `roleHandler := handlers.NewRoleHandler(services.role)`, agregar: `estudianteHandler := handlers.NewEstudianteHandler(services.estudiante)`
6. En `initServer`, actualizar la llamada a `rest.NewRouter(...)` para pasar `estudianteHandler` después de `roleHandler`.

- [ ] **Step 3: Compilar todo el binario**

Run: `go build ./...`
Expected: sin salida (éxito).

- [ ] **Step 4: Correr toda la suite**

Run: `go test ./...`
Expected: PASS (toda la suite, incluidos los tests nuevos).

- [ ] **Step 5: Commit**

```bash
git add internal/presentation/rest/router.go cmd/api/main.go
git commit -m "feat(presentation): wiring de rutas y dependencias de Estudiante"
```

---

## Task 12: Documentación Swagger + README

**Files:**
- Modify: `docs/` (regenerado por swag)
- Modify: `README.md`

- [ ] **Step 1: Regenerar Swagger**

Run: `swag init -g cmd/api/main.go -o docs`
Expected: `docs/swagger.json`, `docs/swagger.yaml`, `docs/docs.go` actualizados con el tag `estudiantes`.

> Si `swag` no está instalado: `go install github.com/swaggo/swag/cmd/swag@latest` y reintentar. Usar el MISMO comando que aparezca en el README/CI del proyecto si difiere.

- [ ] **Step 2: Actualizar el README**

En `README.md`, en la sección de endpoints, agregar el grupo `estudiantes` (GET/POST `/api/v1/estudiantes`, GET/PUT/DELETE `/api/v1/estudiantes/{id}`, POST `/api/v1/estudiantes/{id}/restore`) y los permisos `read:estudiantes` / `manage:estudiantes`, siguiendo el formato de las secciones existentes.

- [ ] **Step 3: Verificar build final**

Run: `go build ./...`
Expected: sin salida (éxito).

- [ ] **Step 4: Commit**

```bash
git add docs README.md
git commit -m "docs(swagger): documentar endpoints de estudiantes"
```

---

## Self-Review

**1. Spec coverage (vs `2026-05-17-convivencia-incidencias-design.md`):**
- Estudiante alta manual ficha mínima (RUT cifrado+hash, nombre cifrado, curso, scope) → Tasks 2, 5, 6, 7 ✔
- Diseñado para import futuro (factory + repo reutilizables, sin lógica de import) → Task 2/3 (factory y puerto agnósticos del origen) ✔
- Cifrado identidad a nivel app (AES+HMAC), patrón email reutilizado → Task 4 ✔
- Log de acceso Ley 21.719 (lecturas auditadas) → Task 5 (`read_estudiante` en `GetByID`) ✔
- RBAC `read:estudiantes`/`manage:estudiantes` + scope → Tasks 9, 11, 5 (`assertScopeAccess`) ✔
- Migraciones golang-migrate (no AutoMigrate) → Task 7 ✔
- Strict TDD (dominio sin infra, servicio con mocks, repo integración, handler httptest) → Tasks 2,4,5,8,10 ✔
- Soft delete + Restore → Tasks 7, 8, 10 ✔
- Fuera de alcance v1 (incidencias, import masivo) → correctamente excluido; es el Plan B ✔

**2. Placeholder scan:** Sin "TBD"/"TODO". Las dos notas de "usar el nombre real del helper" (Task 8) y "comando swag del proyecto" (Task 12) son instrucciones de adaptación a artefactos existentes verificables por el ejecutor, no placeholders de contenido. El código está completo en cada step.

**3. Type consistency:**
- `domain.Estudiante` (campos `Rut`, `RutHash`, `RutEncrypted`, `Nombre`, `NombreEncrypted`, `Curso`, `Scope`) consistente entre Tasks 2, 5, 6, 8.
- `application.EstudianteData` consistente entre Tasks 5 y 10.
- `application.EstudianteService` (firmas `Create/GetByID/Search/UpdateDatos/Delete/Restore`) idéntica entre Task 5 (definición), Task 10 (fake) y Task 11 (wiring).
- `domain.EstudianteRepository` (`FindByID/FindByRutHash/Search/CountSearch/Create/UpdateDatos/Delete/Restore`) idéntica entre Task 3 (puerto), Task 8 (impl) y Task 5 (mock).
- Corrección aplicada inline: `estudianteHandler.Restore` (no `RestoreUser`) en Task 11 Step 1.

---

## Execution Handoff

Plan A completo. El Plan B (Incidencia + expediente + debido proceso) se escribirá sobre esta base una vez mergeado el Plan A.
