// Package cache provee un cache en memoria liviano para la validaciÃ³n de token_version.
//
// Problema que resuelve:
//
//	El JWT embebe token_version como claim "ver". El middleware necesita compararlo
//	contra la BD en cada request para detectar tokens stale (permisos revocados).
//	Sin cache, esto serÃ­a un SELECT extra por request â€” inaceptable en producciÃ³n.
//
// SoluciÃ³n:
//
//	Cache en memoria con TTL de 30 segundos. La ventana mÃ¡xima de invalidaciÃ³n
//	pasa de 15 minutos (duraciÃ³n del JWT) a 30 segundos (TTL del cache).
//	Al cambiar roles/permisos, se llama a Invalidate(userID) para evitar esperar
//	incluso esos 30 segundos.
package cache

import (
	"sync"
	"time"
)

// entry almacena el valor cacheado junto con su tiempo de expiraciÃ³n.
type entry struct {
	version   int
	expiresAt time.Time
}

// TokenVersionCache es un cache en memoria thread-safe para token_version por userID.
// Usa sync.Map internamente para permitir lecturas concurrentes sin contenciÃ³n.
type TokenVersionCache struct {
	store sync.Map
	ttl   time.Duration
}

// NewTokenVersionCache crea un cache con el TTL indicado.
// Un TTL de 30s es un buen balance: la ventana de stale permissions baja de
// 15 minutos a 30 segundos, con un costo de latencia prÃ¡cticamente nulo.
func NewTokenVersionCache(ttl time.Duration) *TokenVersionCache {
	return &TokenVersionCache{ttl: ttl}
}

// Get retorna (version, true) si el valor estÃ¡ en cache y no expirÃ³.
// Retorna (0, false) si no estÃ¡ o expirÃ³.
func (c *TokenVersionCache) Get(userID uint) (int, bool) {
	val, ok := c.store.Load(userID)
	if !ok {
		return 0, false
	}
	e := val.(entry)
	if time.Now().After(e.expiresAt) {
		c.store.Delete(userID)
		return 0, false
	}
	return e.version, true
}

// Set almacena la versiÃ³n para el userID con el TTL configurado.
func (c *TokenVersionCache) Set(userID uint, version int) {
	c.store.Store(userID, entry{
		version:   version,
		expiresAt: time.Now().Add(c.ttl),
	})
}

// Invalidate elimina la entrada del cache para forzar una re-lectura desde DB.
// Llamar siempre que se incrementa token_version (AssignRoles, AssignPermissions).
func (c *TokenVersionCache) Invalidate(userID uint) {
	c.store.Delete(userID)
}
