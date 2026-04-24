package middleware

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// visitor mantiene el token bucket y la última vez que la IP fue vista
type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// IPRateLimiter es un middleware stateful para limitar request por IP
type IPRateLimiter struct {
	ips map[string]*visitor
	mu  sync.Mutex
	r   rate.Limit // Requests por segundo
	b   int        // Ráfaga (burst) permitida
}

// NewIPRateLimiter crea un nuevo limitador y lanza una goroutine para limpiar memoria
func NewIPRateLimiter(r rate.Limit, b int) *IPRateLimiter {
	i := &IPRateLimiter{
		ips: make(map[string]*visitor),
		r:   r,
		b:   b,
	}

	// Goroutine en background que limpia IPs inactivas cada minuto
	// Esto previene memory leaks si recibimos requests de muchas IPs únicas
	go i.cleanupVisitors()

	return i
}

func (i *IPRateLimiter) getVisitor(ip string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()

	v, exists := i.ips[ip]
	if !exists {
		limiter := rate.NewLimiter(i.r, i.b)
		i.ips[ip] = &visitor{limiter, time.Now()}
		return limiter
	}

	v.lastSeen = time.Now()
	return v.limiter
}

func (i *IPRateLimiter) cleanupVisitors() {
	for {
		time.Sleep(time.Minute)

		i.mu.Lock()
		for ip, v := range i.ips {
			// Si la IP no hizo requests en los últimos 3 minutos, la borramos
			if time.Since(v.lastSeen) > 3*time.Minute {
				delete(i.ips, ip)
			}
		}
		i.mu.Unlock()
	}
}

// Middleware retorna la función handler para interceptar el request HTTP
func (i *IPRateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extraer IP limpia (sin puerto)
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}

		limiter := i.getVisitor(ip)
		
		// Si se excedió el límite, rechazamos con 429 Too Many Requests
		if !limiter.Allow() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error": "too many requests, please slow down"}`))
			return
		}

		next.ServeHTTP(w, r)
	})
}
