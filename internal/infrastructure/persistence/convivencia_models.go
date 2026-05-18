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
