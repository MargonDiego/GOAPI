package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/diego/go-api/internal/domain"
	"github.com/diego/go-api/internal/presentation/http/handlers"
	"github.com/diego/go-api/mocks"
)

func TestAuthHandler_Register(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		payload        interface{}
		setupMock      func(m *mocks.MockAuthService)
		expectedStatus int
		expectedBody   string // Parcial de lo que se espera encontrar en el cuerpo
	}{
		{
			name:           "Payload JSON inválido",
			payload:        "esto no es json",
			setupMock:      func(m *mocks.MockAuthService) {},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "invalid json payload",
		},
		{
			name: "Faltan campos obligatorios",
			payload: handlers.AuthRequest{
				Username: "newuser",
				// falta password y email
			},
			setupMock:      func(m *mocks.MockAuthService) {},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "username, password and email are required",
		},
		{
			name: "Error en servicio: Email ya existe",
			payload: handlers.AuthRequest{
				Username: "newuser",
				Password: "password123",
				Email:    "existing@test.com",
			},
			setupMock: func(m *mocks.MockAuthService) {
				m.On("Register", mock.Anything, "newuser", "password123", "existing@test.com").
					Return(domain.ErrEmailAlreadyExists)
			},
			expectedStatus: http.StatusConflict,
			expectedBody:   domain.ErrEmailAlreadyExists.Error(),
		},
		{
			name: "Éxito al registrar usuario",
			payload: handlers.AuthRequest{
				Username: "newuser",
				Password: "password123",
				Email:    "new@test.com",
			},
			setupMock: func(m *mocks.MockAuthService) {
				m.On("Register", mock.Anything, "newuser", "password123", "new@test.com").
					Return(nil)
			},
			expectedStatus: http.StatusCreated,
			expectedBody:   "user registered successfully",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockService := mocks.NewMockAuthService(t)
			tt.setupMock(mockService)

			handler := handlers.NewAuthHandler(mockService)

			var bodyBytes []byte
			if strPayload, ok := tt.payload.(string); ok {
				bodyBytes = []byte(strPayload)
			} else {
				bodyBytes, _ = json.Marshal(tt.payload)
			}

			req := httptest.NewRequest(http.MethodPost, "/api/register", bytes.NewReader(bodyBytes))
			rr := httptest.NewRecorder()

			handler.Register(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)
			assert.Contains(t, rr.Body.String(), tt.expectedBody)
		})
	}
}

func TestAuthHandler_Login(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		payload        interface{}
		setupMock      func(m *mocks.MockAuthService)
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Payload JSON inválido",
			payload:        "invalid json",
			setupMock:      func(m *mocks.MockAuthService) {},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "invalid json payload",
		},
		{
			name: "Credenciales incorrectas (Unauthorized)",
			payload: handlers.AuthRequest{
				Username: "user",
				Password: "wrongpassword",
			},
			setupMock: func(m *mocks.MockAuthService) {
				m.On("Login", mock.Anything, "user", "wrongpassword").
					Return("", "", domain.ErrInvalidCreds)
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   domain.ErrInvalidCreds.Error(),
		},
		{
			name: "Cuenta bloqueada por reintentos (TooManyRequests)",
			payload: handlers.AuthRequest{
				Username: "lockeduser",
				Password: "password123",
			},
			setupMock: func(m *mocks.MockAuthService) {
				m.On("Login", mock.Anything, "lockeduser", "password123").
					Return("", "", domain.ErrAccountLocked)
			},
			expectedStatus: http.StatusTooManyRequests,
			expectedBody:   domain.ErrAccountLocked.Error(),
		},
		{
			name: "Login exitoso",
			payload: handlers.AuthRequest{
				Username: "user",
				Password: "password123",
			},
			setupMock: func(m *mocks.MockAuthService) {
				m.On("Login", mock.Anything, "user", "password123").
					Return("access_token_val", "refresh_token_val", nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "access_token_val", // En el body debe venir el JWT
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockService := mocks.NewMockAuthService(t)
			tt.setupMock(mockService)

			handler := handlers.NewAuthHandler(mockService)

			var bodyBytes []byte
			if strPayload, ok := tt.payload.(string); ok {
				bodyBytes = []byte(strPayload)
			} else {
				bodyBytes, _ = json.Marshal(tt.payload)
			}

			req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(bodyBytes))
			rr := httptest.NewRecorder()

			handler.Login(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)
			assert.Contains(t, rr.Body.String(), tt.expectedBody)
		})
	}
}
