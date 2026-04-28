package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/diego/go-api/internal/application"
	"github.com/diego/go-api/internal/domain"
	appcrypto "github.com/diego/go-api/internal/infrastructure/crypto"
	"github.com/diego/go-api/mocks"
)

func setupTestEncryptorForUserService(t *testing.T) *appcrypto.Encryptor {
	t.Helper()
	key := []byte("12345678901234567890123456789012")
	enc, err := appcrypto.NewEncryptor(key)
	assert.NoError(t, err)
	return enc
}

func TestUserService_GetUserByUsername(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		username      string
		setupMock     func(m *mocks.MockUserRepository)
		expectedUser  *domain.User
		expectedError error
	}{
		{
			name:    "Usuario encontrado por username",
			username: "john",
			setupMock: func(m *mocks.MockUserRepository) {
				m.On("FindByUsername", mock.Anything, "john").Return(&domain.User{ID: 1, Username: "john"}, nil)
			},
			expectedUser: &domain.User{ID: 1, Username: "john"},
			expectedError: nil,
		},
		{
			name:    "Usuario no encontrado por username",
			username: "nonexistent",
			setupMock: func(m *mocks.MockUserRepository) {
				m.On("FindByUsername", mock.Anything, "nonexistent").Return(nil, domain.ErrUserNotFound)
			},
			expectedUser: nil,
			expectedError: domain.ErrUserNotFound,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockUserRepo := mocks.NewMockUserRepository(t)
			mockRoleRepo := mocks.NewMockRoleRepository(t)
			enc := setupTestEncryptorForUserService(t)

			tt.setupMock(mockUserRepo)

			service := application.NewUserService(mockUserRepo, mockRoleRepo, enc)
			ctx := context.Background()

			user, err := service.GetUserByUsername(ctx, tt.username)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.expectedError)
				assert.Nil(t, user)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedUser.ID, user.ID)
				assert.Equal(t, tt.expectedUser.Username, user.Username)
			}
		})
	}
}

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

			mockRoleRepo := mocks.NewMockRoleRepository(t)
			enc := setupTestEncryptorForUserService(t)

			service := application.NewUserService(mockUserRepo, mockRoleRepo, enc)
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
			enc := setupTestEncryptor(t)

			tt.setupUserMock(mockUserRepo)
			tt.setupRoleMock(mockRoleRepo)

			service := application.NewUserService(mockUserRepo, mockRoleRepo, enc)
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

func TestUserService_GetUserByID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		userID       uint
		setupMock    func(m *mocks.MockUserRepository)
		expectedUser *domain.User
		expectedError error
	}{
		{
			name:    "Usuario encontrado",
			userID:  1,
			setupMock: func(m *mocks.MockUserRepository) {
				m.On("FindByID", mock.Anything, uint(1)).Return(&domain.User{ID: 1, Username: "john"}, nil)
			},
			expectedUser: &domain.User{ID: 1, Username: "john"},
			expectedError: nil,
		},
		{
			name:    "Usuario no encontrado",
			userID:  999,
			setupMock: func(m *mocks.MockUserRepository) {
				m.On("FindByID", mock.Anything, uint(999)).Return(nil, domain.ErrUserNotFound)
			},
			expectedUser: nil,
			expectedError: domain.ErrUserNotFound,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockUserRepo := mocks.NewMockUserRepository(t)
			mockRoleRepo := mocks.NewMockRoleRepository(t)
			enc := setupTestEncryptorForUserService(t)

			tt.setupMock(mockUserRepo)

			service := application.NewUserService(mockUserRepo, mockRoleRepo, enc)
			ctx := context.Background()

			user, err := service.GetUserByID(ctx, tt.userID)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.expectedError)
				assert.Nil(t, user)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedUser.ID, user.ID)
				assert.Equal(t, tt.expectedUser.Username, user.Username)
			}
		})
	}
}

func TestUserService_CreateUser(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		username     string
		password     string
		email        string
		setupMock    func(m *mocks.MockUserRepository, mr *mocks.MockRoleRepository)
		expectedError error
	}{
		{
			name:      "Usuario creado exitosamente",
			username:  "john",
			password:  "password123",
			email:     "john@test.com",
			setupMock: func(m *mocks.MockUserRepository, mr *mocks.MockRoleRepository) {
				m.On("FindByUsername", mock.Anything, "john").Return(nil, domain.ErrUserNotFound)
				m.On("FindByEmailHash", mock.Anything, mock.AnythingOfType("string")).Return(nil, domain.ErrUserNotFound)
				mr.On("FindByName", mock.Anything, "User").Return(&domain.Role{ID: 1, Name: "User"}, nil)
				m.On("Save", mock.Anything, mock.AnythingOfType("*domain.User")).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:      "Usuario ya existe",
			username:  "john",
			password:  "password123",
			email:     "",
			setupMock: func(m *mocks.MockUserRepository, mr *mocks.MockRoleRepository) {
				m.On("FindByUsername", mock.Anything, "john").Return(&domain.User{ID: 1, Username: "john"}, nil)
			},
			expectedError: domain.ErrUserAlreadyExists,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockUserRepo := mocks.NewMockUserRepository(t)
			mockRoleRepo := mocks.NewMockRoleRepository(t)
			enc := setupTestEncryptorForUserService(t)

			tt.setupMock(mockUserRepo, mockRoleRepo)

			service := application.NewUserService(mockUserRepo, mockRoleRepo, enc)
			ctx := context.Background()

			err := service.CreateUser(ctx, tt.username, tt.password, tt.email)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestUserService_UpdateUser(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		userID       uint
		newUsername  string
		setupMock    func(m *mocks.MockUserRepository)
		expectedError error
	}{
		{
			name:         "Usuario actualizado",
			userID:       1,
			newUsername:  "johnnew",
			setupMock: func(m *mocks.MockUserRepository) {
				m.On("FindByID", mock.Anything, uint(1)).Return(&domain.User{ID: 1, Username: "john"}, nil)
				m.On("Save", mock.Anything, mock.AnythingOfType("*domain.User")).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:         "Usuario no encontrado",
			userID:      999,
			newUsername: "johnnew",
			setupMock: func(m *mocks.MockUserRepository) {
				m.On("FindByID", mock.Anything, uint(999)).Return(nil, domain.ErrUserNotFound)
			},
			expectedError: domain.ErrUserNotFound,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockUserRepo := mocks.NewMockUserRepository(t)
			mockRoleRepo := mocks.NewMockRoleRepository(t)
			enc := setupTestEncryptorForUserService(t)

			tt.setupMock(mockUserRepo)

			service := application.NewUserService(mockUserRepo, mockRoleRepo, enc)
			ctx := context.Background()

			err := service.UpdateUser(ctx, tt.userID, tt.newUsername, "")

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestUserService_DeleteUser(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		userID       uint
		setupMock    func(m *mocks.MockUserRepository)
		expectedError error
	}{
		{
			name:    "Usuario eliminado",
			userID:  1,
			setupMock: func(m *mocks.MockUserRepository) {
				m.On("Delete", mock.Anything, uint(1)).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:    "Error al eliminar",
			userID:  1,
			setupMock: func(m *mocks.MockUserRepository) {
				m.On("Delete", mock.Anything, uint(1)).Return(errors.New("db error"))
			},
			expectedError: errors.New("db error"),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockUserRepo := mocks.NewMockUserRepository(t)
			mockRoleRepo := mocks.NewMockRoleRepository(t)
			enc := setupTestEncryptorForUserService(t)

			tt.setupMock(mockUserRepo)

			service := application.NewUserService(mockUserRepo, mockRoleRepo, enc)
			ctx := context.Background()

			err := service.DeleteUser(ctx, tt.userID)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
