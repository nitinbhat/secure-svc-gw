package auth

import (
	"sync"
	"time"
)

// NonceStore is the interface the Verifier needs for replay defence.
// The default in-memory implementation is sufficient for a single-replica
// gateway; use NewRedisNonceStore for multi-replica deployments.
type NonceStore interface {
	// CheckAndStore returns true iff jti was NOT already present.
	// It atomically marks the jti as seen (up to exp) if not.
	CheckAndStore(jti string, exp time.Time) bool
}

// nonceCache is an in-memory NonceStore keyed by JWT `jti`.
//
// A jti is stored until its token's own `exp` -- after that the token is
// already invalid on time grounds so a duplicate cannot be replayed anyway.
// A background sweeper reclaims memory on a fixed cadence.
type nonceCache struct {
	mu    sync.Mutex
	items map[string]time.Time // jti -> exp
	ttl   time.Duration
}

func newNonceCache(ttl time.Duration) *nonceCache {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	c := &nonceCache{items: make(map[string]time.Time), ttl: ttl}
	go c.sweep()
	return c
}

// NewInMemoryNonceStore returns the default in-memory NonceStore.
// Use this when Redis is not configured.
func NewInMemoryNonceStore(ttl time.Duration) NonceStore {
	return newNonceCache(ttl)
}

// CheckAndStore satisfies NonceStore. The mutation is atomic with the
// existence check to avoid a TOCTOU race between two concurrent replays.
func (c *nonceCache) CheckAndStore(jti string, exp time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, seen := c.items[jti]; seen {
		return false
	}
	if exp.IsZero() {
		exp = time.Now().Add(c.ttl)
	}
	c.items[jti] = exp
	return true
}

func (c *nonceCache) sweep() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for range t.C {
		now := time.Now()
		c.mu.Lock()
		for k, exp := range c.items {
			if now.After(exp) {
				delete(c.items, k)
			}
		}
		c.mu.Unlock()
	}
}
