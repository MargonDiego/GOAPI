package handlers_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/diego/go-api/internal/presentation/http/handlers"
)

type mockPinger struct {
	err error
}

func (m *mockPinger) PingContext(ctx context.Context) error {
	return m.err
}

func TestHealthHandler_Liveness(t *testing.T) {
	t.Parallel()

	handler := handlers.NewHealthHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/health/liveness", nil)
	rr := httptest.NewRecorder()

	handler.Liveness(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "OK", rr.Body.String())
}

func TestHealthHandler_Readiness(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		pinger         *mockPinger
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "BD respondiendo",
			pinger:         &mockPinger{err: nil},
			expectedStatus: http.StatusOK,
			expectedBody:   "READY",
		},
		{
			name:           "BD caída",
			pinger:         &mockPinger{err: errors.New("timeout")},
			expectedStatus: http.StatusServiceUnavailable,
			expectedBody:   "Database Unavailable",
		},
		{
			name:           "Sin pinger configurado (fallback gracefully)",
			pinger:         nil,
			expectedStatus: http.StatusOK,
			expectedBody:   "READY",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var pinger handlers.DatabasePinger
			if tt.pinger != nil {
				pinger = tt.pinger
			}
			
			handler := handlers.NewHealthHandler(pinger)

			req := httptest.NewRequest(http.MethodGet, "/health/readiness", nil)
			rr := httptest.NewRecorder()

			handler.Readiness(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)
			assert.Contains(t, rr.Body.String(), tt.expectedBody)
		})
	}
}
