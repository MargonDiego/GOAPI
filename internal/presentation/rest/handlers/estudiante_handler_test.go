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
