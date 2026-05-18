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
