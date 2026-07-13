package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

// RedisNonceStore is a distributed NonceStore backed by Redis.
//
// It uses SET NX EX which is atomic on any single Redis node (or a Cluster
// with a hash-slot key) so there is no TOCTOU window even under concurrent
// replicas. On any Redis error the store fails closed (returns false) to
// prevent replay attacks from slipping through during transient outages.
type RedisNonceStore struct {
	client redis.Cmdable
}

// NewRedisNonceStore connects to Redis at the given URL and pings it to
// verify connectivity at startup.
// url format: "redis://[:password@]host[:port][/db]"
func NewRedisNonceStore(url string) (*RedisNonceStore, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("redis url: %w", err)
	}
	c := redis.NewClient(opt)
	if err := c.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("redis ping: %w", err)
	}
	return &RedisNonceStore{client: c}, nil
}

// CheckAndStore satisfies NonceStore. Returns true iff jti was not already
// present (i.e. this request is not a replay).
func (r *RedisNonceStore) CheckAndStore(jti string, exp time.Time) bool {
	ttl := time.Until(exp)
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	// SET nonce:<jti> 1 EX <ttl> NX  — returns true only when the key is new.
	ok, err := r.client.SetNX(context.Background(), "nonce:"+jti, 1, ttl).Result()
	if err != nil {
		// Fail closed: deny the request rather than risk allowing a replay.
		return false
	}
	return ok
}
