package auth

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
)

// ---------------------------------------------------------------------------
// In-memory nonce store
// ---------------------------------------------------------------------------

func TestNonce_NewAccepted(t *testing.T) {
	store := NewInMemoryNonceStore(time.Minute)
	exp := time.Now().Add(time.Minute)
	if !store.CheckAndStore("jti-1", exp) {
		t.Fatal("first call should return true")
	}
}

func TestNonce_SameRejected(t *testing.T) {
	store := NewInMemoryNonceStore(time.Minute)
	exp := time.Now().Add(time.Minute)
	store.CheckAndStore("jti-1", exp)
	if store.CheckAndStore("jti-1", exp) {
		t.Fatal("second call with same jti should return false")
	}
}

func TestNonce_DifferentAccepted(t *testing.T) {
	store := NewInMemoryNonceStore(time.Minute)
	exp := time.Now().Add(time.Minute)
	if !store.CheckAndStore("jti-a", exp) {
		t.Fatal("jti-a first use should succeed")
	}
	if !store.CheckAndStore("jti-b", exp) {
		t.Fatal("jti-b first use should succeed")
	}
}

// TestNonce_ExpiredReuse: after the sweeper removes an expired entry the
// same jti may be used again.
func TestNonce_ExpiredReuse(t *testing.T) {
	cache := newNonceCache(time.Minute)
	jti := "reuse-jti"

	// Directly seed the map with an already-expired entry.
	pastExp := time.Now().Add(-time.Second)
	cache.mu.Lock()
	cache.items[jti] = pastExp
	cache.mu.Unlock()

	// Simulate the sweeper: delete entries whose exp < now.
	now := time.Now()
	cache.mu.Lock()
	for k, e := range cache.items {
		if now.After(e) {
			delete(cache.items, k)
		}
	}
	cache.mu.Unlock()

	// jti should be accepted again after sweep.
	if !cache.CheckAndStore(jti, time.Now().Add(time.Minute)) {
		t.Fatal("expired jti should be accepted after sweep removes it")
	}
}

// TestNonce_ConcurrentReplay: 100 goroutines race on the same jti.
// Exactly one must succeed; all others must be rejected.
func TestNonce_ConcurrentReplay(t *testing.T) {
	store := NewInMemoryNonceStore(time.Minute)
	const n = 100
	jti := "race-jti"
	exp := time.Now().Add(time.Minute)

	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if store.CheckAndStore(jti, exp) {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()

	if got := accepted.Load(); got != 1 {
		t.Fatalf("exactly 1 goroutine should succeed, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// Redis nonce store (backed by miniredis so no real server needed)
// ---------------------------------------------------------------------------

func newRedisStore(t *testing.T) (*RedisNonceStore, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return &RedisNonceStore{client: client}, mr
}

func TestRedisNonce_NewAccepted(t *testing.T) {
	store, _ := newRedisStore(t)
	if !store.CheckAndStore("rjti-1", time.Now().Add(time.Minute)) {
		t.Fatal("first Redis call should return true")
	}
}

func TestRedisNonce_SameRejected(t *testing.T) {
	store, _ := newRedisStore(t)
	exp := time.Now().Add(time.Minute)
	store.CheckAndStore("rjti-1", exp)
	if store.CheckAndStore("rjti-1", exp) {
		t.Fatal("duplicate Redis call should return false")
	}
}

// TestRedisNonce_TTLExpiry: miniredis FastForward simulates time passing;
// after the key expires Redis accepts the jti again.
func TestRedisNonce_TTLExpiry(t *testing.T) {
	store, mr := newRedisStore(t)
	jti := "expire-jti"
	exp := time.Now().Add(2 * time.Second)

	if !store.CheckAndStore(jti, exp) {
		t.Fatal("first call should succeed")
	}
	// Advance miniredis clock past the key's TTL.
	mr.FastForward(3 * time.Second)
	// Key is gone → should be accepted as a fresh nonce.
	if !store.CheckAndStore(jti, time.Now().Add(time.Minute)) {
		t.Fatal("jti should be accepted again after TTL expiry")
	}
}

// TestRedisNonce_Unavailable: Redis is down → CheckAndStore must fail closed
// (return false) so replays cannot slip through during an outage.
func TestRedisNonce_Unavailable(t *testing.T) {
	mr := miniredis.RunT(t)
	addr := mr.Addr()
	mr.Close() // tear down before using the store

	client := redis.NewClient(&redis.Options{
		Addr:        addr,
		DialTimeout: 100 * time.Millisecond,
		MaxRetries:  0,
	})
	store := &RedisNonceStore{client: client}

	if store.CheckAndStore("any-jti", time.Now().Add(time.Minute)) {
		t.Fatal("unavailable Redis must fail closed (return false)")
	}
}

// TestRedisNonce_ConcurrentReplay: 50 goroutines race on the same jti against
// a real (miniredis) Redis instance; SET NX guarantees exactly one winner.
func TestRedisNonce_ConcurrentReplay(t *testing.T) {
	store, _ := newRedisStore(t)
	const n = 50
	jti := "redis-race-jti"
	exp := time.Now().Add(time.Minute)

	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if store.CheckAndStore(jti, exp) {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()

	if got := accepted.Load(); got != 1 {
		t.Fatalf("exactly 1 goroutine should succeed via Redis SET NX, got %d", got)
	}
}
