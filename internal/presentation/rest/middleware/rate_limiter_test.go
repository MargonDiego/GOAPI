package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/diego/go-api/internal/presentation/rest/middleware"
	"github.com/stretchr/testify/assert"
)

func TestIPRateLimiter_Middleware(t *testing.T) {
	t.Parallel()

	t.Run("Permite requests dentro del límite", func(t *testing.T) {
		limiter := middleware.NewIPRateLimiter(10, 10)
		handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Rechaza con 429 al exceder el burst", func(t *testing.T) {
		limiter := middleware.NewIPRateLimiter(1, 1) // 1 req/s, burst 1
		handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// Primera petición: OK (consume el burst de 1)
		req1 := httptest.NewRequest(http.MethodGet, "/", nil)
		rr1 := httptest.NewRecorder()
		handler.ServeHTTP(rr1, req1)
		assert.Equal(t, http.StatusOK, rr1.Code)

		// Segunda petición inmediata: 429 (burst agotado)
		req2 := httptest.NewRequest(http.MethodGet, "/", nil)
		rr2 := httptest.NewRecorder()
		handler.ServeHTTP(rr2, req2)
		assert.Equal(t, http.StatusTooManyRequests, rr2.Code)
	})
}
