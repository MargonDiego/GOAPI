package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/diego/go-api/internal/application"
	"github.com/diego/go-api/internal/domain"
)

// mockRoleRepository es un mock manual de domain.RoleRepository usando testify/mock.
// Permite aislar la capa de aplicación sin tocar la base de datos PostgreSQL.
type mockRoleRepository struct {
	mock.Mock
}

func (m *mockRoleRepository) Create(ctx context.Context, role *domain.Role) error {
	args := m.Called(ctx, role)
	return args.Error(0)
}

func (m *mockRoleRepository) FindByID(ctx context.Context, id uint) (*domain.Role, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Role), args.Error(1)
}

func (m *mockRoleRepository) FindAll(ctx context.Context) ([]domain.Role, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.Role), args.Error(1)
}

func (m *mockRoleRepository) Update(ctx context.Context, role *domain.Role) error {
	args := m.Called(ctx, role)
	return args.Error(0)
}

func (m *mockRoleRepository) FindPermissionsByIDs(ctx context.Context, ids []uint) ([]domain.Permission, error) {
	args := m.Called(ctx, ids)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.Permission), args.Error(1)
}

func (m *mockRoleRepository) FindAllPermissions(ctx context.Context) ([]domain.Permission, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.Permission), args.Error(1)
}

func (m *mockRoleRepository) FindRolesByIDs(ctx context.Context, ids []uint) ([]domain.Role, error) {
	args := m.Called(ctx, ids)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.Role), args.Error(1)
}

func (m *mockRoleRepository) FindByName(ctx context.Context, name string) (*domain.Role, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Role), args.Error(1)
}

func (m *mockRoleRepository) Delete(ctx context.Context, id uint) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockRoleRepository) CreatePermission(ctx context.Context, name string) error {
	args := m.Called(ctx, name)
	return args.Error(0)
}

func TestRoleService_CreateRole(t *testing.T) {
	t.Parallel()

	// Tipo de Test: Unit Test (Caja blanca)
	// Propósito: Validar que el caso de uso CreateRole verifique el input,
	// llame al repositorio subyacente correctamente, y propague errores según corresponda.

	// Casos definidos mediante Table-Driven Tests
	tests := []struct {
		name          string
		roleName      string
		setupMock     func(m *mockRoleRepository)
		expectedError error
		expectedRole  *domain.Role
	}{
		{
			name:     "Éxito al crear rol",
			roleName: "Manager",
			setupMock: func(m *mockRoleRepository) {
				// Arrange: Esperamos que llame a Create con el rol "Manager" y no devuelva error.
				m.On("Create", mock.Anything, &domain.Role{Name: "Manager"}).
					Run(func(args mock.Arguments) {
						// Simulamos el comportamiento de GORM de asignar ID al guardarse
						roleArg := args.Get(1).(*domain.Role)
						roleArg.ID = 1
					}).Return(nil)
			},
			expectedError: nil,
			expectedRole:  &domain.Role{ID: 1, Name: "Manager"},
		},
		{
			name:          "Falla por nombre vacío",
			roleName:      "",
			setupMock:     func(m *mockRoleRepository) {}, // No debería llamar al repo
			expectedError: domain.ErrInvalidInput,
			expectedRole:  nil,
		},
		{
			name:     "Falla al persistir en base de datos",
			roleName: "Admin",
			setupMock: func(m *mockRoleRepository) {
				m.On("Create", mock.Anything, &domain.Role{Name: "Admin"}).
					Return(errors.New("db error"))
			},
			expectedError: errors.New("failed to create role: db error"), // Se espera envoltorio de error
			expectedRole:  nil,
		},
	}

	for _, tt := range tests {
		tt := tt // Capture variable local para rutinas paralelas
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Arrange
			mockRepo := new(mockRoleRepository)
			tt.setupMock(mockRepo)

			service := application.NewRoleService(mockRepo)
			ctx := context.Background()

			// Act
			got, err := service.CreateRole(ctx, tt.roleName)

			// Assert
			if tt.expectedError != nil {
				// Verificamos si la cadena de errores contiene nuestro error esperado
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
				assert.Nil(t, got)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, got)
				assert.Equal(t, tt.expectedRole.ID, got.ID)
				assert.Equal(t, tt.expectedRole.Name, got.Name)
			}

			// Validar que todas las expectativas del mock se cumplieron
			mockRepo.AssertExpectations(t)
		})
	}
}
