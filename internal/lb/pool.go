// Package lb implements the gateway's load balancer.
//
// # Algorithm: Power-of-Two-Choices (P2C) with EWMA latency scoring
//
// For each request we:
//  1. take a snapshot of currently healthy backends
//  2. pick two at random
//  3. send to whichever has the lower score, where
//     score = ewma_latency_ms * (in_flight + 1)
//
// P2C is O(1), stateless across requests, and provably close to
// least-loaded without the thundering-herd problem of true least-loaded.
// EWMA gives us fast reaction to slow backends without flapping.
//
// The health checker owns the healthy-set membership; the LB only reads it.
package lb

import (
	"math"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nibhat/secure-svc-gw/internal/config"
)

// Backend is a single upstream endpoint plus the live stats we maintain
// against it.
type Backend struct {
	ID   string
	Addr string

	// atomically-updated liveness bit, owned by the health checker
	healthy atomic.Bool

	// in-flight request counter (atomic)
	inflight atomic.Int64

	// EWMA of observed latency in milliseconds; guarded by mu
	mu       sync.Mutex
	ewmaMs   float64
	hasStats bool
}

func (b *Backend) IsHealthy() bool { return b.healthy.Load() }

// SetHealthy flips the liveness bit. When a backend transitions from
// unhealthy back to healthy we also wipe its EWMA -- otherwise a stale
// pre-ejection latency can starve the recovered backend under P2C
// because its two peers now have fresher (and smaller) EWMA values.
func (b *Backend) SetHealthy(v bool) {
	prev := b.healthy.Swap(v)
	if v && !prev {
		b.mu.Lock()
		b.ewmaMs = 0
		b.hasStats = false
		b.mu.Unlock()
	}
}
func (b *Backend) Inflight() int64 { return b.inflight.Load() }
func (b *Backend) Acquire()        { b.inflight.Add(1) }
func (b *Backend) Release()        { b.inflight.Add(-1) }

// RecordLatency updates the EWMA. Alpha = 0.3 gives a half-life of ~2
// samples which reacts quickly to a backend becoming slow.
func (b *Backend) RecordLatency(d time.Duration) {
	const alpha = 0.3
	sample := float64(d.Milliseconds())
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.hasStats {
		b.ewmaMs = sample
		b.hasStats = true
		return
	}
	b.ewmaMs = alpha*sample + (1-alpha)*b.ewmaMs
}

func (b *Backend) score() float64 {
	b.mu.Lock()
	ewma := b.ewmaMs
	b.mu.Unlock()
	if ewma == 0 {
		ewma = 1 // avoid multiplying by zero on first pick
	}
	return ewma * float64(b.Inflight()+1)
}

// Pool is the set of backends belonging to one logical service.
type Pool struct {
	Service  string
	backends []*Backend
}

func NewPool(service string, cfg []config.Backend) *Pool {
	p := &Pool{Service: service, backends: make([]*Backend, 0, len(cfg))}
	for _, b := range cfg {
		bk := &Backend{ID: b.ID, Addr: b.Addr}
		// Start optimistic; the health checker will flip us false on the
		// first failure. Starting pessimistic would drop the first N
		// requests during a cold start.
		bk.healthy.Store(true)
		p.backends = append(p.backends, bk)
	}
	return p
}

func (p *Pool) All() []*Backend { return p.backends }

// Healthy returns a fresh slice of currently-healthy backends. Callers may
// hold on to this snapshot for the duration of one request.
func (p *Pool) Healthy() []*Backend {
	out := make([]*Backend, 0, len(p.backends))
	for _, b := range p.backends {
		if b.IsHealthy() {
			out = append(out, b)
		}
	}
	return out
}

// Pick returns one backend per the P2C algorithm, or nil if the pool has
// no healthy members (the caller should return 503).
func (p *Pool) Pick() *Backend {
	h := p.Healthy()
	switch len(h) {
	case 0:
		return nil
	case 1:
		return h[0]
	}
	i := rand.Intn(len(h))
	j := rand.Intn(len(h) - 1)
	if j >= i {
		j++
	}
	a, b := h[i], h[j]
	if a.score() <= b.score() {
		return a
	}
	return b
}

// Total returns the number of configured backends (healthy or not) -- used
// for logging/metrics dimensions.
func (p *Pool) Total() int { return len(p.backends) }

// SafeScore is exposed so tests can assert LB behaviour.
func SafeScore(ewma float64, inflight int64) float64 {
	if ewma == 0 {
		ewma = 1
	}
	return math.Max(ewma, 0) * float64(inflight+1)
}
