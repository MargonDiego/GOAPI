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
	"github.com/diego/go-api/mocks"
)

func TestRoleHandler_CreateRole(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		payload        interface{}
		setupMock      func(m *mocks.MockRoleService)
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "JSON inválido",
			payload:        "invalid",
			setupMock:      func(m *mocks.MockRoleService) {},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "invalid json payload",
		},
		{
			name:    "Error de servicio (ej: nombre vacío)",
			payload: handlers.RoleCreateRequest{Name: ""},
			setupMock: func(m *mocks.MockRoleService) {
				m.On("CreateRole", mock.Anything, "").Return((*domain.Role)(nil), domain.ErrInvalidInput)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   domain.ErrInvalidInput.Error(),
		},
		{
			name:    "Éxito al crear rol",
			payload: handlers.RoleCreateRequest{Name: "Admin"},
			setupMock: func(m *mocks.MockRoleService) {
				m.On("CreateRole", mock.Anything, "Admin").Return(&domain.Role{ID: 1, Name: "Admin"}, nil)
			},
			expectedStatus: http.StatusCreated,
			expectedBody:   "Admin",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockService := mocks.NewMockRoleService(t)
			tt.setupMock(mockService)

			handler := handlers.NewRoleHandler(mockService)

			var bodyBytes []byte
			if strPayload, ok := tt.payload.(string); ok {
				bodyBytes = []byte(strPayload)
			} else {
				bodyBytes, _ = json.Marshal(tt.payload)
			}

			req := httptest.NewRequest(http.MethodPost, "/api/roles", bytes.NewReader(bodyBytes))
			rr := httptest.NewRecorder()

			handler.CreateRole(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)
			assert.Contains(t, rr.Body.String(), tt.expectedBody)
		})
	}
}

func TestRoleHandler_GetRoles(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		setupMock      func(m *mocks.MockRoleService)
		expectedStatus int
		expectedBody   string
	}{
		{
			name: "Error al obtener roles",
			setupMock: func(m *mocks.MockRoleService) {
				m.On("GetRoles", mock.Anything).Return(nil, errors.New("db error"))
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "failed to get roles",
		},
		{
			name: "Éxito (Lista vacía no debe ser null)",
			setupMock: func(m *mocks.MockRoleService) {
				m.On("GetRoles", mock.Anything).Return([]domain.Role{}, nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "[]",
		},
		{
			name: "Éxito con roles",
			setupMock: func(m *mocks.MockRoleService) {
				roles := []domain.Role{
					{ID: 1, Name: "Admin", Permissions: []domain.Permission{{ID: 1, Name: "all"}}},
				}
				m.On("GetRoles", mock.Anything).Return(roles, nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "Admin",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockService := mocks.NewMockRoleService(t)
			tt.setupMock(mockService)

			handler := handlers.NewRoleHandler(mockService)

			req := httptest.NewRequest(http.MethodGet, "/api/roles", nil)
			rr := httptest.NewRecorder()

			handler.GetRoles(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)
			assert.Contains(t, rr.Body.String(), tt.expectedBody)
		})
	}
}

func TestRoleHandler_GetPermissions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		setupMock      func(m *mocks.MockRoleService)
		expectedStatus int
		expectedBody   string
	}{
		{
			name: "Error de servicio",
			setupMock: func(m *mocks.MockRoleService) {
				m.On("GetPermissions", mock.Anything).Return(nil, errors.New("db error"))
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "failed to get permissions",
		},
		{
			name: "Éxito con permisos",
			setupMock: func(m *mocks.MockRoleService) {
				perms := []domain.Permission{{ID: 1, Name: "read:users"}}
				m.On("GetPermissions", mock.Anything).Return(perms, nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "read:users",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockService := mocks.NewMockRoleService(t)
			tt.setupMock(mockService)

			handler := handlers.NewRoleHandler(mockService)

			req := httptest.NewRequest(http.MethodGet, "/api/permissions", nil)
			rr := httptest.NewRecorder()

			handler.GetPermissions(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)
			assert.Contains(t, rr.Body.String(), tt.expectedBody)
		})
	}
}

func TestRoleHandler_AssignPermissions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		urlID          string
		payload        interface{}
		setupMock      func(m *mocks.MockRoleService)
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "ID inválido en URL",
			urlID:          "invalid",
			payload:        handlers.AssignPermissionsRequest{PermissionIDs: []uint{1}},
			setupMock:      func(m *mocks.MockRoleService) {},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "invalid role id",
		},
		{
			name:           "JSON inválido",
			urlID:          "1",
			payload:        "invalid json",
			setupMock:      func(m *mocks.MockRoleService) {},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "invalid json payload",
		},
		{
			name:  "Error del servicio (ej: permiso inexistente)",
			urlID: "1",
			payload: handlers.AssignPermissionsRequest{PermissionIDs: []uint{99}},
			setupMock: func(m *mocks.MockRoleService) {
				m.On("AssignPermissionsToRole", mock.Anything, uint(1), []uint{99}).Return(domain.ErrInvalidInput)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   domain.ErrInvalidInput.Error(),
		},
		{
			name:  "Éxito",
			urlID: "1",
			payload: handlers.AssignPermissionsRequest{PermissionIDs: []uint{1, 2}},
			setupMock: func(m *mocks.MockRoleService) {
				m.On("AssignPermissionsToRole", mock.Anything, uint(1), []uint{1, 2}).Return(nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "permissions assigned successfully",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockService := mocks.NewMockRoleService(t)
			tt.setupMock(mockService)

			handler := handlers.NewRoleHandler(mockService)

			var bodyBytes []byte
			if strPayload, ok := tt.payload.(string); ok {
				bodyBytes = []byte(strPayload)
			} else {
				bodyBytes, _ = json.Marshal(tt.payload)
			}

			req := httptest.NewRequest(http.MethodPut, "/api/roles/"+tt.urlID+"/permissions", bytes.NewReader(bodyBytes))
			
			r := mux.NewRouter()
			r.HandleFunc("/api/roles/{id}/permissions", handler.AssignPermissions)

			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)
			assert.Contains(t, rr.Body.String(), tt.expectedBody)
		})
	}
}
