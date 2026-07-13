// Package health runs active health checks against every configured
// backend and flips the Backend.healthy bit that the LB reads.
//
// # Semantics
//
//   - probe every `interval` (default 2s) with a short timeout
//   - `failThreshold` consecutive failures  -> mark UNHEALTHY
//   - `passThreshold` consecutive successes -> mark HEALTHY again
//
// The two thresholds are the classic anti-flap pattern: a single slow probe
// should not shift traffic, and a single lucky probe should not restore a
// broken backend.
//
// Health probes go over the SAME mTLS config used for real traffic, so a
// backend whose cert is not signed by our CA (spoofed backend) fails the
// probe with a TLS handshake error and is removed from the pool without
// ever serving a client request.
package health

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/nibhat/secure-svc-gw/internal/lb"
	"github.com/nibhat/secure-svc-gw/internal/metrics"
)

type Checker struct {
	pool          *lb.Pool
	client        *http.Client
	healthPath    string
	interval      time.Duration
	failThreshold int
	passThreshold int

	// mu protects fails and passes; record() is called from concurrent probe goroutines.
	mu     sync.Mutex
	fails  map[string]int
	passes map[string]int
}

func NewChecker(pool *lb.Pool, tlsCfg *tls.Config, healthPath string, interval time.Duration) *Checker {
	return &Checker{
		pool: pool,
		client: &http.Client{
			Timeout:   1500 * time.Millisecond,
			Transport: &http.Transport{TLSClientConfig: tlsCfg, MaxIdleConnsPerHost: 4},
		},
		healthPath:    healthPath,
		interval:      interval,
		failThreshold: 3,
		passThreshold: 2,
		fails:         make(map[string]int),
		passes:        make(map[string]int),
	}
}

// Run blocks until ctx is cancelled. Probes run in parallel per tick so a
// single slow backend does not delay the others.
func (c *Checker) Run(ctx context.Context) {
	// initial probe so the healthy set is meaningful before the first tick
	c.tick(ctx)
	t := time.NewTicker(c.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.tick(ctx)
		}
	}
}

func (c *Checker) tick(ctx context.Context) {
	for _, b := range c.pool.All() {
		go c.probe(ctx, b)
	}
}

func (c *Checker) probe(ctx context.Context, b *lb.Backend) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, b.Addr+c.healthPath, nil)
	resp, err := c.client.Do(req)
	ok := err == nil && resp.StatusCode < 400
	if resp != nil {
		resp.Body.Close()
	}
	c.record(b, ok, err)
}

func (c *Checker) record(b *lb.Backend, ok bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if ok {
		c.fails[b.ID] = 0
		c.passes[b.ID]++
		if !b.IsHealthy() && c.passes[b.ID] >= c.passThreshold {
			b.SetHealthy(true)
			metrics.BackendHealthy.WithLabelValues(c.pool.Service, b.ID).Set(1)
			slog.Info("backend restored",
				"decision", "route",
				"reason", "health_recovered",
				"target_service", c.pool.Service,
				"upstream", b.ID,
			)
		} else if b.IsHealthy() {
			metrics.BackendHealthy.WithLabelValues(c.pool.Service, b.ID).Set(1)
		}
		return
	}
	c.passes[b.ID] = 0
	c.fails[b.ID]++
	if b.IsHealthy() && c.fails[b.ID] >= c.failThreshold {
		b.SetHealthy(false)
		metrics.BackendHealthy.WithLabelValues(c.pool.Service, b.ID).Set(0)
		slog.Warn("backend ejected",
			"decision", "route",
			"reason", "backend_unhealthy",
			"target_service", c.pool.Service,
			"upstream", b.ID,
			"err", errStr(err),
		)
	}
}

func errStr(e error) string {
	if e == nil {
		return ""
	}
	return e.Error()
}
