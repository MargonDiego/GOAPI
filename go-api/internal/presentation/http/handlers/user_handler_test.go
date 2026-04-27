package handlers_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/diego/go-api/internal/domain"
	"github.com/diego/go-api/internal/presentation/http/handlers"
	"github.com/diego/go-api/internal/presentation/http/middleware"
	"github.com/diego/go-api/mocks"
)

func TestUserHandler_GetMe(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		session        *middleware.UserSession
		setupMock      func(m *mocks.MockUserService)
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Falta contexto de usuario",
			session:        nil,
			setupMock:      func(m *mocks.MockUserService) {},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "user context missing",
		},
		{
			name: "Usuario no encontrado",
			session: &middleware.UserSession{Username: "unknown"},
			setupMock: func(m *mocks.MockUserService) {
				m.On("GetUserByUsername", mock.Anything, "unknown").Return(nil, domain.ErrUserNotFound)
			},
			expectedStatus: http.StatusNotFound,
			expectedBody:   domain.ErrUserNotFound.Error(),
		},
		{
			name: "Error interno del servicio",
			session: &middleware.UserSession{Username: "error_user"},
			setupMock: func(m *mocks.MockUserService) {
				m.On("GetUserByUsername", mock.Anything, "error_user").Return(nil, errors.New("db error"))
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "internal server error",
		},
		{
			name: "Éxito al obtener perfil",
			session: &middleware.UserSession{Username: "johndoe"},
			setupMock: func(m *mocks.MockUserService) {
				user := &domain.User{ID: 1, Username: "johndoe"}
				m.On("GetUserByUsername", mock.Anything, "johndoe").Return(user, nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "johndoe",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockService := mocks.NewMockUserService(t)
			tt.setupMock(mockService)

			handler := handlers.NewUserHandler(mockService)

			req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
			if tt.session != nil {
				ctx := middleware.ContextWithSession(req.Context(), *tt.session)
				req = req.WithContext(ctx)
			}
			rr := httptest.NewRecorder()

			handler.GetMe(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)
			assert.Contains(t, rr.Body.String(), tt.expectedBody)
		})
	}
}

func TestUserHandler_GetAll(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		query          string
		setupMock      func(m *mocks.MockUserService)
		expectedStatus int
		expectedBody   string
	}{
		{
			name:  "Paginación correcta",
			query: "?page=2&size=5",
			setupMock: func(m *mocks.MockUserService) {
				users := []domain.User{{ID: 1, Username: "u1"}}
				m.On("GetAllUsers", mock.Anything, 2, 5).Return(users, nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "u1",
		},
		{
			name:  "Paginación con fallbacks por defecto",
			query: "?page=invalid&size=-1",
			setupMock: func(m *mocks.MockUserService) {
				users := []domain.User{{ID: 2, Username: "u2"}}
				m.On("GetAllUsers", mock.Anything, 1, 10).Return(users, nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "u2",
		},
		{
			name:  "Error de BD",
			query: "",
			setupMock: func(m *mocks.MockUserService) {
				m.On("GetAllUsers", mock.Anything, 1, 10).Return(nil, errors.New("db error"))
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "failed to list users",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockService := mocks.NewMockUserService(t)
			tt.setupMock(mockService)

			handler := handlers.NewUserHandler(mockService)

			req := httptest.NewRequest(http.MethodGet, "/api/users"+tt.query, nil)
			rr := httptest.NewRecorder()

			handler.GetAll(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)
			assert.Contains(t, rr.Body.String(), tt.expectedBody)
		})
	}
}

func TestUserHandler_AssignRoles(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		urlID          string
		payload        interface{}
		setupMock      func(m *mocks.MockUserService)
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "ID inválido en URL",
			urlID:          "invalid",
			payload:        handlers.AssignRolesRequest{RoleIDs: []uint{1, 2}},
			setupMock:      func(m *mocks.MockUserService) {},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "invalid user id",
		},
		{
			name:           "JSON inválido",
			urlID:          "1",
			payload:        "invalid json",
			setupMock:      func(m *mocks.MockUserService) {},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "invalid json payload",
		},
		{
			name:  "Error del servicio",
			urlID: "1",
			payload: handlers.AssignRolesRequest{RoleIDs: []uint{1}},
			setupMock: func(m *mocks.MockUserService) {
				m.On("AssignRolesToUser", mock.Anything, uint(1), []uint{1}).Return(domain.ErrInvalidInput)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   domain.ErrInvalidInput.Error(),
		},
		{
			name:  "Éxito",
			urlID: "1",
			payload: handlers.AssignRolesRequest{RoleIDs: []uint{1, 2}},
			setupMock: func(m *mocks.MockUserService) {
				m.On("AssignRolesToUser", mock.Anything, uint(1), []uint{1, 2}).Return(nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "roles assigned successfully",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockService := mocks.NewMockUserService(t)
			tt.setupMock(mockService)

			handler := handlers.NewUserHandler(mockService)

			var bodyBytes []byte
			if strPayload, ok := tt.payload.(string); ok {
				bodyBytes = []byte(strPayload)
			} else {
				bodyBytes, _ = json.Marshal(tt.payload)
			}

			req := httptest.NewRequest(http.MethodPut, "/api/users/"+tt.urlID+"/roles", bytes.NewReader(bodyBytes))
			
			// Configuramos el mux.Router para inyectar los path params
			r := mux.NewRouter()
			r.HandleFunc("/api/users/{id}/roles", handler.AssignRoles)

			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)
			assert.Contains(t, rr.Body.String(), tt.expectedBody)
		})
	}
}
