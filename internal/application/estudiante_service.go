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
