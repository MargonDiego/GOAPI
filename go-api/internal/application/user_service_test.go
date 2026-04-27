package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/diego/go-api/internal/application"
	"github.com/diego/go-api/internal/domain"
	"github.com/diego/go-api/mocks"
)

func TestUserService_GetAllUsers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		page          int
		size          int
		setupMock     func(m *mocks.MockUserRepository)
		expectedUsers []domain.User
		expectedError error
	}{
		{
			name: "Éxito con paginación válida",
			page: 2,
			size: 5,
			setupMock: func(m *mocks.MockUserRepository) {
				users := []domain.User{{ID: 1, Username: "user1"}, {ID: 2, Username: "user2"}}
				m.On("FindAll", mock.Anything, 2, 5).Return(users, nil)
			},
			expectedUsers: []domain.User{{ID: 1, Username: "user1"}, {ID: 2, Username: "user2"}},
			expectedError: nil,
		},
		{
			name: "Sanitización de página inválida y tamaño inválido",
			page: -5,
			size: 200,
			setupMock: func(m *mocks.MockUserRepository) {
				// El servicio debe sobreescribir page=-5 a page=1 y size=200 a size=10
				m.On("FindAll", mock.Anything, 1, 10).Return([]domain.User{}, nil)
			},
			expectedUsers: []domain.User{},
			expectedError: nil,
		},
		{
			name: "Error en base de datos al listar",
			page: 1,
			size: 10,
			setupMock: func(m *mocks.MockUserRepository) {
				m.On("FindAll", mock.Anything, 1, 10).Return(nil, errors.New("db timeout"))
			},
			expectedUsers: nil,
			expectedError: errors.New("failed to list users: db timeout"),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockUserRepo := mocks.NewMockUserRepository(t)
			tt.setupMock(mockUserRepo)
			
			// RoleRepo no se usa en GetAllUsers
			mockRoleRepo := mocks.NewMockRoleRepository(t)

			service := application.NewUserService(mockUserRepo, mockRoleRepo)
			ctx := context.Background()

			users, err := service.GetAllUsers(ctx, tt.page, tt.size)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
				assert.Nil(t, users)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedUsers, users)
			}
		})
	}
}

func TestUserService_AssignRolesToUser(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		userID        uint
		roleIDs       []uint
		setupUserMock func(m *mocks.MockUserRepository)
		setupRoleMock func(m *mocks.MockRoleRepository)
		expectedError error
	}{
		{
			name:    "Error: usuario no existe",
			userID:  99,
			roleIDs: []uint{1, 2},
			setupUserMock: func(m *mocks.MockUserRepository) {
				m.On("FindByID", mock.Anything, uint(99)).Return(nil, domain.ErrUserNotFound)
			},
			setupRoleMock: func(m *mocks.MockRoleRepository) {
				// No debe ser llamado
			},
			expectedError: domain.ErrUserNotFound,
		},
		{
			name:    "Error: rol inexistente detectado",
			userID:  1,
			roleIDs: []uint{1, 2, 99},
			setupUserMock: func(m *mocks.MockUserRepository) {
				m.On("FindByID", mock.Anything, uint(1)).Return(&domain.User{ID: 1}, nil)
			},
			setupRoleMock: func(m *mocks.MockRoleRepository) {
				// Pedimos 3 roles, pero BD devuelve solo 2
				roles := []domain.Role{{ID: 1}, {ID: 2}}
				m.On("FindRolesByIDs", mock.Anything, []uint{1, 2, 99}).Return(roles, nil)
			},
			expectedError: domain.ErrInvalidInput,
		},
		{
			name:    "Éxito al asignar roles",
			userID:  1,
			roleIDs: []uint{1, 2},
			setupUserMock: func(m *mocks.MockUserRepository) {
				m.On("FindByID", mock.Anything, uint(1)).Return(&domain.User{ID: 1}, nil)
				roles := []domain.Role{{ID: 1}, {ID: 2}}
				m.On("UpdateRoles", mock.Anything, uint(1), roles).Return(nil)
			},
			setupRoleMock: func(m *mocks.MockRoleRepository) {
				roles := []domain.Role{{ID: 1}, {ID: 2}}
				m.On("FindRolesByIDs", mock.Anything, []uint{1, 2}).Return(roles, nil)
			},
			expectedError: nil,
		},
		{
			name:    "Éxito limpiando roles (lista vacía)",
			userID:  1,
			roleIDs: []uint{},
			setupUserMock: func(m *mocks.MockUserRepository) {
				m.On("FindByID", mock.Anything, uint(1)).Return(&domain.User{ID: 1}, nil)
				var roles []domain.Role // nil o slice vacío
				m.On("UpdateRoles", mock.Anything, uint(1), roles).Return(nil)
			},
			setupRoleMock: func(m *mocks.MockRoleRepository) {
				// No debe llamar a buscar roles
			},
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockUserRepo := mocks.NewMockUserRepository(t)
			mockRoleRepo := mocks.NewMockRoleRepository(t)
			
			tt.setupUserMock(mockUserRepo)
			tt.setupRoleMock(mockRoleRepo)

			service := application.NewUserService(mockUserRepo, mockRoleRepo)
			ctx := context.Background()

			err := service.AssignRolesToUser(ctx, tt.userID, tt.roleIDs)

			if tt.expectedError != nil {
				assert.Error(t, err)
				// validamos que en la cadena de errores esté el error real (Is)
				if errors.Is(tt.expectedError, domain.ErrUserNotFound) || errors.Is(tt.expectedError, domain.ErrInvalidInput) {
					assert.ErrorIs(t, err, tt.expectedError)
				} else {
					assert.Contains(t, err.Error(), tt.expectedError.Error())
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
