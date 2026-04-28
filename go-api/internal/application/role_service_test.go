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
				// El servicio primero verifica unicidad llamando a FindByName.
				m.On("FindByName", mock.Anything, "Manager").Return(nil, domain.ErrRoleNotFound)
				// Si no existe, procede a crear.
				m.On("Create", mock.Anything, &domain.Role{Name: "Manager"}).
					Run(func(args mock.Arguments) {
						// Simulamos el comportamiento de GORM de asignar ID al guardarse.
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
			setupMock:     func(m *mockRoleRepository) {}, // Validación previa: no debe llamar al repo.
			expectedError: domain.ErrInvalidInput,
			expectedRole:  nil,
		},
		{
			name:     "Falla por rol duplicado",
			roleName: "Admin",
			setupMock: func(m *mockRoleRepository) {
				// FindByName retorna el rol existente → debe fallar con ErrRoleAlreadyExists.
				m.On("FindByName", mock.Anything, "Admin").Return(&domain.Role{ID: 1, Name: "Admin"}, nil)
			},
			expectedError: domain.ErrRoleAlreadyExists,
			expectedRole:  nil,
		},
		{
			name:     "Falla al persistir en base de datos",
			roleName: "Editor",
			setupMock: func(m *mockRoleRepository) {
				m.On("FindByName", mock.Anything, "Editor").Return(nil, domain.ErrRoleNotFound)
				m.On("Create", mock.Anything, &domain.Role{Name: "Editor"}).
					Return(errors.New("db error"))
			},
			expectedError: errors.New("failed to create role: db error"),
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
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
				assert.Nil(t, got)
			} else {
				// Caso éxito: verificar que se retorna el rol con los valores correctos.
				assert.NoError(t, err)
				assert.NotNil(t, got)
				assert.Equal(t, tt.expectedRole.ID, got.ID)
				assert.Equal(t, tt.expectedRole.Name, got.Name)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

func TestRoleService_CreatePermission(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		permName      string
		setupMock     func(m *mockRoleRepository)
		expectedError error
	}{
		{
			name:     "Permiso creado exitosamente",
			permName: "read:users",
			setupMock: func(m *mockRoleRepository) {
				// El servicio primero verifica unicidad con FindAllPermissions.
				m.On("FindAllPermissions", mock.Anything).Return([]domain.Permission{}, nil)
				m.On("CreatePermission", mock.Anything, "read:users").Return(nil)
			},
			expectedError: nil,
		},
		{
			name:     "Nombre vacío",
			permName: "",
			setupMock: func(m *mockRoleRepository) {
				// Validación previa: no debe llamar al repo.
			},
			expectedError: domain.ErrInvalidInput,
		},
		{
			name:     "Falla por permiso duplicado",
			permName: "read:users",
			setupMock: func(m *mockRoleRepository) {
				// FindAllPermissions retorna el permiso ya existente.
				m.On("FindAllPermissions", mock.Anything).Return(
					[]domain.Permission{{ID: 1, Name: "read:users"}}, nil,
				)
			},
			expectedError: domain.ErrPermissionAlreadyExists,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockRepo := new(mockRoleRepository)
			tt.setupMock(mockRepo)

			service := application.NewRoleService(mockRepo)
			ctx := context.Background()

			err := service.CreatePermission(ctx, tt.permName)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
			mockRepo.AssertExpectations(t)
		})
	}
}

func TestRoleService_GetRoleByID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		roleID      uint
		setupMock    func(m *mockRoleRepository)
		expectedRole *domain.Role
		expectedError error
	}{
		{
			name:    "Rol encontrado",
			roleID: 1,
			setupMock: func(m *mockRoleRepository) {
				m.On("FindByID", mock.Anything, uint(1)).Return(&domain.Role{ID: 1, Name: "Admin"}, nil)
			},
			expectedRole: &domain.Role{ID: 1, Name: "Admin"},
			expectedError: nil,
		},
		{
			name:    "Rol no encontrado",
			roleID: 999,
			setupMock: func(m *mockRoleRepository) {
				m.On("FindByID", mock.Anything, uint(999)).Return(nil, domain.ErrRoleNotFound)
			},
			expectedRole: nil,
			expectedError: domain.ErrRoleNotFound,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockRepo := new(mockRoleRepository)
			tt.setupMock(mockRepo)

			service := application.NewRoleService(mockRepo)
			ctx := context.Background()

			role, err := service.GetRoleByID(ctx, tt.roleID)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.expectedError)
				assert.Nil(t, role)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedRole.ID, role.ID)
				assert.Equal(t, tt.expectedRole.Name, role.Name)
			}
			mockRepo.AssertExpectations(t)
		})
	}
}

func TestRoleService_UpdateRole(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		roleID       uint
		newName      string
		setupMock    func(m *mockRoleRepository)
		expectedError error
	}{
		{
			name:    "Rol actualizado",
			roleID: 1,
			newName: "SuperAdmin",
			setupMock: func(m *mockRoleRepository) {
				m.On("FindByID", mock.Anything, uint(1)).Return(&domain.Role{ID: 1, Name: "Admin"}, nil)
				m.On("Update", mock.Anything, mock.AnythingOfType("*domain.Role")).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:    "Nombre vacío",
			roleID: 1,
			newName: "",
			setupMock: func(m *mockRoleRepository) {
				// No debe llamar al mock
			},
			expectedError: domain.ErrInvalidInput,
		},
		{
			name:    "Rol no encontrado",
			roleID: 999,
			newName: "NewRole",
			setupMock: func(m *mockRoleRepository) {
				m.On("FindByID", mock.Anything, uint(999)).Return(nil, domain.ErrRoleNotFound)
			},
			expectedError: domain.ErrRoleNotFound,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockRepo := new(mockRoleRepository)
			tt.setupMock(mockRepo)

			service := application.NewRoleService(mockRepo)
			ctx := context.Background()

			err := service.UpdateRole(ctx, tt.roleID, tt.newName)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
			mockRepo.AssertExpectations(t)
		})
	}
}

func TestRoleService_DeleteRole(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		roleID       uint
		setupMock    func(m *mockRoleRepository)
		expectedError error
	}{
		{
			name:    "Rol eliminado",
			roleID: 1,
			setupMock: func(m *mockRoleRepository) {
				m.On("Delete", mock.Anything, uint(1)).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:    "Error al eliminar",
			roleID: 1,
			setupMock: func(m *mockRoleRepository) {
				m.On("Delete", mock.Anything, uint(1)).Return(errors.New("db error"))
			},
			expectedError: errors.New("db error"),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockRepo := new(mockRoleRepository)
			tt.setupMock(mockRepo)

			service := application.NewRoleService(mockRepo)
			ctx := context.Background()

			err := service.DeleteRole(ctx, tt.roleID)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				assert.NoError(t, err)
			}
			mockRepo.AssertExpectations(t)
		})
	}
}
