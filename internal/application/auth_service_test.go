package application_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/MargonDiego/GOAPI/internal/application"
	"github.com/MargonDiego/GOAPI/internal/domain"
	appcrypto "github.com/MargonDiego/GOAPI/internal/infrastructure/crypto"
	"github.com/MargonDiego/GOAPI/mocks"
	"golang.org/x/crypto/bcrypt"
)

func setupTestEncryptor(t *testing.T) *appcrypto.Encryptor {
	t.Helper()
	key := []byte("12345678901234567890123456789012")
	enc, err := appcrypto.NewEncryptor(key)
	assert.NoError(t, err)
	return enc
}

func TestAuthService_Register(t *testing.T) {
	t.Parallel()

	jwtSecret := []byte("super_secret")
	enc := setupTestEncryptor(t)

	tests := []struct {
		name          string
		username      string
		password      string
		email         string
		setupUserMock func(m *mocks.MockUserRepository)
		setupRoleMock func(m *mocks.MockRoleRepository)
		expectedError error
	}{
		{
			name:          "Error de validacion: contrasena corta",
			username:      "testuser",
			password:      "123",
			email:         "test@test.com",
			setupUserMock: func(m *mocks.MockUserRepository) {},
			setupRoleMock: func(m *mocks.MockRoleRepository) {},
			expectedError: domain.ErrInvalidInput,
		},
		{
			name:          "Error de validacion: email vacio",
			username:      "testuser",
			password:      "validpassword123",
			email:         "",
			setupUserMock: func(m *mocks.MockUserRepository) {},
			setupRoleMock: func(m *mocks.MockRoleRepository) {},
			expectedError: domain.ErrInvalidInput,
		},
		{
			name:     "Error: username ya existe",
			username: "existinguser",
			password: "validpassword123",
			email:    "new@test.com",
			setupUserMock: func(m *mocks.MockUserRepository) {
				m.On("FindByUsername", mock.Anything, "existinguser").Return(&domain.User{}, nil)
			},
			setupRoleMock: func(m *mocks.MockRoleRepository) {},
			expectedError: domain.ErrUserAlreadyExists,
		},
		{
			name:     "Error: email ya existe",
			username: "newuser",
			password: "validpassword123",
			email:    "existing@test.com",
			setupUserMock: func(m *mocks.MockUserRepository) {
				m.On("FindByUsername", mock.Anything, "newuser").Return(nil, domain.ErrUserNotFound)
				emailHash := enc.HashEmail("existing@test.com")
				m.On("FindByEmailHash", mock.Anything, emailHash).Return(&domain.User{}, nil)
			},
			setupRoleMock: func(m *mocks.MockRoleRepository) {},
			expectedError: domain.ErrEmailAlreadyExists,
		},
		{
			name:     "Exito: registro completado",
			username: "newuser",
			password: "validpassword123",
			email:    "new@test.com",
			setupUserMock: func(m *mocks.MockUserRepository) {
				m.On("FindByUsername", mock.Anything, "newuser").Return(nil, domain.ErrUserNotFound)
				emailHash := enc.HashEmail("new@test.com")
				m.On("FindByEmailHash", mock.Anything, emailHash).Return(nil, domain.ErrUserNotFound)
				m.On("Create", mock.Anything, mock.AnythingOfType("*domain.User")).Return(nil)
			},
			setupRoleMock: func(m *mocks.MockRoleRepository) {
				defaultRole := &domain.Role{ID: 1, Name: "User"}
				m.On("FindByName", mock.Anything, "User").Return(defaultRole, nil)
			},
			expectedError: nil,
		},
		{
			name:     "Falla interna al buscar rol por defecto",
			username: "newuser",
			password: "validpassword123",
			email:    "new@test.com",
			setupUserMock: func(m *mocks.MockUserRepository) {
				m.On("FindByUsername", mock.Anything, "newuser").Return(nil, domain.ErrUserNotFound)
				emailHash := enc.HashEmail("new@test.com")
				m.On("FindByEmailHash", mock.Anything, emailHash).Return(nil, domain.ErrUserNotFound)
			},
			setupRoleMock: func(m *mocks.MockRoleRepository) {
				m.On("FindByName", mock.Anything, "User").Return(nil, errors.New("db error"))
			},
			expectedError: errors.New("could not retrieve default role: db error"),
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

			service := application.NewAuthService(mockUserRepo, mockRoleRepo, jwtSecret, enc)
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

func TestAuthService_Logout(t *testing.T) {
	t.Parallel()

	jwtSecret := []byte("super_secret")
	enc := setupTestEncryptor(t)

	tests := []struct {
		name          string
		userID        uint
		setupMock     func(m *mocks.MockUserRepository)
		expectedError error
	}{
		{
			name:   "Logout exitoso",
			userID: 1,
			setupMock: func(m *mocks.MockUserRepository) {
				m.On("FindByID", mock.Anything, uint(1)).Return(&domain.User{ID: 1, Username: "testuser"}, nil)
				m.On("DeleteAllRefreshTokens", mock.Anything, uint(1)).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:   "Usuario no encontrado",
			userID: 999,
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

			mockRepo := mocks.NewMockUserRepository(t)
			tt.setupMock(mockRepo)
			mockRoleRepo := mocks.NewMockRoleRepository(t)

			service := application.NewAuthService(mockRepo, mockRoleRepo, jwtSecret, enc)
			ctx := context.Background()

			err := service.Logout(ctx, tt.userID)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAuthService_RefreshTokens(t *testing.T) {
	t.Parallel()

	jwtSecret := []byte("super_secret")
	enc := setupTestEncryptor(t)

	tests := []struct {
		name          string
		refreshToken  string
		userID        uint
		setupMock     func(m *mocks.MockUserRepository)
		expectedError error
	}{
		{
			name:         "Exito: refresh token valido",
			refreshToken: "valid-refresh-token",
			userID:       1,
			setupMock: func(m *mocks.MockUserRepository) {
				m.On("GetRefreshToken", mock.Anything, "valid-refresh-token").Return(&domain.RefreshToken{
					Token:     "valid-refresh-token",
					UserID:    1,
					ExpiresAt: time.Now().Add(24 * time.Hour),
				}, nil)
				m.On("FindByID", mock.Anything, uint(1)).Return(&domain.User{
					ID:       1,
					Username: "testuser",
				}, nil)
				m.On("DeleteRefreshToken", mock.Anything, "valid-refresh-token").Return(nil)
				m.On("SaveRefreshToken", mock.Anything, mock.AnythingOfType("*domain.RefreshToken")).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:         "Error: refresh token invalido",
			refreshToken: "invalid-token",
			userID:       1,
			setupMock: func(m *mocks.MockUserRepository) {
				m.On("GetRefreshToken", mock.Anything, "invalid-token").Return(nil, domain.ErrInvalidToken)
			},
			expectedError: domain.ErrInvalidToken,
		},
		{
			name:         "Error: refresh token expirado",
			refreshToken: "expired-token",
			userID:       1,
			setupMock: func(m *mocks.MockUserRepository) {
				m.On("GetRefreshToken", mock.Anything, "expired-token").Return(&domain.RefreshToken{
					Token:     "expired-token",
					UserID:    1,
					ExpiresAt: time.Now().Add(-1 * time.Hour),
				}, nil)
				m.On("DeleteRefreshToken", mock.Anything, "expired-token").Return(nil)
			},
			expectedError: domain.ErrInvalidToken,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockRepo := mocks.NewMockUserRepository(t)
			tt.setupMock(mockRepo)
			mockRoleRepo := mocks.NewMockRoleRepository(t)

			service := application.NewAuthService(mockRepo, mockRoleRepo, jwtSecret, enc)
			ctx := context.Background()

			_, _, err := service.RefreshTokens(ctx, tt.refreshToken)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAuthService_Login(t *testing.T) {
	t.Parallel()

	jwtSecret := []byte("super_secret_key_for_testing_32bytes!")
	enc := setupTestEncryptor(t)

	// Hash de contraseÃ±a vÃ¡lida para tests (bcrypt.GenerateFromPassword es determinista por salt aleatorio,
	// asÃ­ que generamos una por cada test case que lo necesite).
	validHash, _ := bcrypt.GenerateFromPassword([]byte("validpassword123"), bcrypt.DefaultCost)

	tests := []struct {
		name          string
		username      string
		password      string
		setupUserMock func(m *mocks.MockUserRepository)
		setupRoleMock func(m *mocks.MockRoleRepository)
		wantErr       error
		wantTokens    bool // true si esperamos tokens vÃ¡lidos
	}{
		{
			name:     "Login exitoso con Fat JWT y refresh token",
			username: "testuser",
			password: "validpassword123",
			setupUserMock: func(m *mocks.MockUserRepository) {
				m.On("FindByUsername", mock.Anything, "testuser").Return(&domain.User{
					ID:           1,
					Username:     "testuser",
					PasswordHash: string(validHash),
					TokenVersion: 1,
				}, nil)
				// ResetFailedAttempts â†’ Update
				m.On("Update", mock.Anything, mock.MatchedBy(func(u *domain.User) bool {
					return u.ID == 1 && u.FailedAttempts == 0 && u.LockedUntil == nil
				})).Return(nil)
				// SaveRefreshToken
				m.On("SaveRefreshToken", mock.Anything, mock.AnythingOfType("*domain.RefreshToken")).Return(nil)
			},
			setupRoleMock: func(m *mocks.MockRoleRepository) {},
			wantErr:       nil,
			wantTokens:    true,
		},
		{
			name:     "Credenciales invalidas: contrasena incorrecta",
			username: "testuser",
			password: "wrongpassword",
			setupUserMock: func(m *mocks.MockUserRepository) {
				m.On("FindByUsername", mock.Anything, "testuser").Return(&domain.User{
					ID:           1,
					Username:     "testuser",
					PasswordHash: string(validHash),
				}, nil)
				// RecordFailedAttempt â†’ Update
				m.On("Update", mock.Anything, mock.AnythingOfType("*domain.User")).Return(nil)
			},
			setupRoleMock: func(m *mocks.MockRoleRepository) {},
			wantErr:       domain.ErrInvalidCreds,
			wantTokens:    false,
		},
		{
			name:     "Usuario no encontrado",
			username: "ghost",
			password: "validpassword123",
			setupUserMock: func(m *mocks.MockUserRepository) {
				m.On("FindByUsername", mock.Anything, "ghost").Return(nil, domain.ErrUserNotFound)
			},
			setupRoleMock: func(m *mocks.MockRoleRepository) {},
			wantErr:       domain.ErrInvalidCreds,
			wantTokens:    false,
		},
		{
			name:     "Cuenta bloqueada: LockedUntil en el futuro",
			username: "lockeduser",
			password: "validpassword123",
			setupUserMock: func(m *mocks.MockUserRepository) {
				lockedUntil := time.Now().Add(10 * time.Minute)
				m.On("FindByUsername", mock.Anything, "lockeduser").Return(&domain.User{
					ID:           2,
					Username:     "lockeduser",
					PasswordHash: string(validHash),
					LockedUntil:  &lockedUntil,
				}, nil)
			},
			setupRoleMock: func(m *mocks.MockRoleRepository) {},
			wantErr:       domain.ErrAccountLocked,
			wantTokens:    false,
		},
		{
			name:     "Bloqueo tras alcanzar MaxFailedAttempts",
			username: "bruteforce",
			password: "wrongpassword",
			setupUserMock: func(m *mocks.MockUserRepository) {
				m.On("FindByUsername", mock.Anything, "bruteforce").Return(&domain.User{
					ID:             3,
					Username:       "bruteforce",
					PasswordHash:   string(validHash),
					FailedAttempts: 4, // Ya tiene 4, este es el 5to â†’ bloqueo
				}, nil)
				m.On("Update", mock.Anything, mock.AnythingOfType("*domain.User")).Return(nil)
			},
			setupRoleMock: func(m *mocks.MockRoleRepository) {},
			wantErr:       domain.ErrAccountLocked,
			wantTokens:    false,
		},
		{
			name:     "DoS prevention: contrasena > 72 caracteres",
			username: "testuser",
			password: "this_is_a_very_long_password_that_exceeds_72_characters_to_test_dos_prevention_xxxxxxxxx",
			setupUserMock: func(m *mocks.MockUserRepository) {
				// No debe llamar a BD â€” se rechaza antes
			},
			setupRoleMock: func(m *mocks.MockRoleRepository) {},
			wantErr:       domain.ErrInvalidCreds,
			wantTokens:    false,
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

			service := application.NewAuthService(mockUserRepo, mockRoleRepo, jwtSecret, enc)
			ctx := context.Background()

			accessToken, refreshToken, err := service.Login(ctx, tt.username, tt.password)

			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Empty(t, accessToken)
				assert.Empty(t, refreshToken)
			} else {
				assert.NoError(t, err)
				if tt.wantTokens {
					assert.NotEmpty(t, accessToken)
					assert.NotEmpty(t, refreshToken)
				}
			}
		})
	}
}
