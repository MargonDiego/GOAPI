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
