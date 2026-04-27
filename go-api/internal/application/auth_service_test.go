package application_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/diego/go-api/internal/application"
	"github.com/diego/go-api/internal/domain"
	appcrypto "github.com/diego/go-api/internal/infrastructure/crypto"
	"github.com/diego/go-api/mocks"
)

func setupTestEncryptor(t *testing.T) *appcrypto.Encryptor {
	t.Helper()
	key := []byte("12345678901234567890123456789012") // 32 bytes exactos
	enc, err := appcrypto.NewEncryptor(key)
	assert.NoError(t, err)
	return enc
}

func TestAuthService_Register(t *testing.T) {
	t.Parallel()

	// Arrange Global
	jwtSecret := []byte("super_secret")
	enc := setupTestEncryptor(t)

	tests := []struct {
		name          string
		username      string
		password      string
		email         string
		setupMock     func(m *mocks.MockUserRepository)
		expectedError error
	}{
		{
			name:     "Error de validación: contraseña corta",
			username: "testuser",
			password: "123",
			email:    "test@test.com",
			setupMock: func(m *mocks.MockUserRepository) {
				// No se llama a BD
			},
			expectedError: domain.ErrInvalidInput,
		},
		{
			name:     "Error de validación: email vacío",
			username: "testuser",
			password: "validpassword123",
			email:    "",
			setupMock: func(m *mocks.MockUserRepository) {
				// No se llama a BD
			},
			expectedError: domain.ErrInvalidInput,
		},
		{
			name:     "Error: username ya existe",
			username: "existinguser",
			password: "validpassword123",
			email:    "new@test.com",
			setupMock: func(m *mocks.MockUserRepository) {
				m.On("FindByUsername", mock.Anything, "existinguser").Return(&domain.User{}, nil)
			},
			expectedError: domain.ErrUserAlreadyExists,
		},
		{
			name:     "Error: email ya existe",
			username: "newuser",
			password: "validpassword123",
			email:    "existing@test.com",
			setupMock: func(m *mocks.MockUserRepository) {
				m.On("FindByUsername", mock.Anything, "newuser").Return(nil, domain.ErrUserNotFound)
				
				emailHash := enc.HashEmail("existing@test.com")
				m.On("FindByEmailHash", mock.Anything, emailHash).Return(&domain.User{}, nil)
			},
			expectedError: domain.ErrEmailAlreadyExists,
		},
		{
			name:     "Éxito: registro completado",
			username: "newuser",
			password: "validpassword123",
			email:    "new@test.com",
			setupMock: func(m *mocks.MockUserRepository) {
				m.On("FindByUsername", mock.Anything, "newuser").Return(nil, domain.ErrUserNotFound)
				
				emailHash := enc.HashEmail("new@test.com")
				m.On("FindByEmailHash", mock.Anything, emailHash).Return(nil, domain.ErrUserNotFound)
				
				defaultRole := domain.Role{ID: 1, Name: "User"}
				m.On("FindRoleByName", mock.Anything, "User").Return(defaultRole, nil)
				
				// En GORM el repositorio guarda el puntero
				m.On("Save", mock.Anything, mock.AnythingOfType("*domain.User")).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:     "Falla interna al buscar rol por defecto",
			username: "newuser",
			password: "validpassword123",
			email:    "new@test.com",
			setupMock: func(m *mocks.MockUserRepository) {
				m.On("FindByUsername", mock.Anything, "newuser").Return(nil, domain.ErrUserNotFound)
				
				emailHash := enc.HashEmail("new@test.com")
				m.On("FindByEmailHash", mock.Anything, emailHash).Return(nil, domain.ErrUserNotFound)
				
				m.On("FindRoleByName", mock.Anything, "User").Return(domain.Role{}, errors.New("db error"))
			},
			expectedError: errors.New("could not retrieve default role: db error"),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Instanciamos el mock autogenerado por Mockery
			mockRepo := mocks.NewMockUserRepository(t)
			tt.setupMock(mockRepo)

			service := application.NewAuthService(mockRepo, jwtSecret, enc)
			ctx := context.Background()

			err := service.Register(ctx, tt.username, tt.password, tt.email)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAuthService_Login(t *testing.T) {
	t.Parallel()

	jwtSecret := []byte("super_secret")
	enc := setupTestEncryptor(t)

	tests := []struct {
		name          string
		username      string
		password      string
		setupMock     func(m *mocks.MockUserRepository)
		expectedError error
	}{
		{
			name:     "Error: credenciales inválidas (usuario no encontrado)",
			username: "unknown",
			password: "password123",
			setupMock: func(m *mocks.MockUserRepository) {
				m.On("FindByUsername", mock.Anything, "unknown").Return(nil, domain.ErrUserNotFound)
			},
			expectedError: domain.ErrInvalidCreds,
		},
		{
			name:     "Error: cuenta bloqueada",
			username: "lockeduser",
			password: "password123",
			setupMock: func(m *mocks.MockUserRepository) {
				lockedTime := time.Now().Add(1 * time.Hour)
				lockedUser := &domain.User{
					FailedAttempts: 5,
					LockedUntil:    &lockedTime,
				}
				m.On("FindByUsername", mock.Anything, "lockeduser").Return(lockedUser, nil)
			},
			expectedError: domain.ErrAccountLocked,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockRepo := mocks.NewMockUserRepository(t)
			tt.setupMock(mockRepo)

			service := application.NewAuthService(mockRepo, jwtSecret, enc)
			ctx := context.Background()

			accessToken, refreshToken, err := service.Login(ctx, tt.username, tt.password)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.expectedError)
				assert.Empty(t, accessToken)
				assert.Empty(t, refreshToken)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, accessToken)
				assert.NotEmpty(t, refreshToken)
			}
		})
	}
}
