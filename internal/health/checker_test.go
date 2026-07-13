package health

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nibhat/secure-svc-gw/internal/config"
	"github.com/nibhat/secure-svc-gw/internal/lb"
)

// newTestChecker builds a Checker with a nil HTTP client (only safe when
// calling record directly, not probe).
func newTestChecker(pool *lb.Pool) *Checker {
	return &Checker{
		pool:          pool,
		failThreshold: 3,
		passThreshold: 2,
		fails:         make(map[string]int),
		passes:        make(map[string]int),
	}
}

func singleBackendPool() (*lb.Pool, *lb.Backend) {
	p := lb.NewPool("svc", []config.Backend{{ID: "b1", Addr: "http://b1"}})
	return p, p.All()[0]
}

// ---------------------------------------------------------------------------
// Threshold semantics
// ---------------------------------------------------------------------------

// Healthy → 3 failures → unhealthy.
func TestChecker_ThreeFailuresEjectBackend(t *testing.T) {
	pool, b := singleBackendPool()
	c := newTestChecker(pool)

	if !b.IsHealthy() {
		t.Fatal("backend should start healthy")
	}

	c.record(b, false, errors.New("timeout"))
	c.record(b, false, errors.New("timeout"))
	if !b.IsHealthy() {
		t.Fatal("should still be healthy after 2 failures (below threshold)")
	}

	c.record(b, false, errors.New("timeout"))
	if b.IsHealthy() {
		t.Fatal("should be unhealthy after 3 consecutive failures")
	}
}

// Unhealthy → 2 successes → healthy.
func TestChecker_TwoSuccessesRestoreBackend(t *testing.T) {
	pool, b := singleBackendPool()
	c := newTestChecker(pool)

	// Eject.
	c.record(b, false, errors.New("x"))
	c.record(b, false, errors.New("x"))
	c.record(b, false, errors.New("x"))

	if b.IsHealthy() {
		t.Fatal("should be unhealthy after 3 failures")
	}

	// One success is not enough.
	c.record(b, true, nil)
	if b.IsHealthy() {
		t.Fatal("one success should not restore (passThreshold=2)")
	}

	// Second success restores.
	c.record(b, true, nil)
	if !b.IsHealthy() {
		t.Fatal("two consecutive successes should restore the backend")
	}
}

// Anti-flap: success streak resets on any failure; 1 success then failure
// must not restore a dead backend.
func TestChecker_NoFlapSuccessInterrupted(t *testing.T) {
	pool, b := singleBackendPool()
	c := newTestChecker(pool)

	// Eject.
	c.record(b, false, errors.New("x"))
	c.record(b, false, errors.New("x"))
	c.record(b, false, errors.New("x"))

	// 1 success then a failure.
	c.record(b, true, nil)
	c.record(b, false, errors.New("x"))

	if b.IsHealthy() {
		t.Fatal("interrupted success streak must not restore the backend")
	}
}

// Two backends: failure on one must not affect the other.
func TestChecker_FailuresArePerBackend(t *testing.T) {
	pool := lb.NewPool("svc", []config.Backend{
		{ID: "b1", Addr: "http://b1"},
		{ID: "b2", Addr: "http://b2"},
	})
	c := newTestChecker(pool)
	b1, b2 := pool.All()[0], pool.All()[1]

	c.record(b1, false, errors.New("x"))
	c.record(b1, false, errors.New("x"))
	c.record(b1, false, errors.New("x"))

	if b1.IsHealthy() {
		t.Fatal("b1 should be unhealthy")
	}
	if !b2.IsHealthy() {
		t.Fatal("b2 should remain healthy")
	}
}

// ---------------------------------------------------------------------------
// Live HTTP probe via httptest
// ---------------------------------------------------------------------------

// A healthy endpoint (200 OK) should restore an unhealthy backend after two probes.
func TestChecker_ProbeHealthyServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	pool := lb.NewPool("svc", []config.Backend{{ID: "b1", Addr: srv.URL}})
	b := pool.All()[0]
	b.SetHealthy(false) // start ejected

	c := NewChecker(pool, nil, "/healthz", time.Second)
	ctx := context.Background()

	c.probe(ctx, b)
	c.probe(ctx, b) // second success → restored

	if !b.IsHealthy() {
		t.Fatal("backend should be healthy after two successful probes")
	}
}

// A 500 response counts as a failed probe.
func TestChecker_ProbeSickServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	pool := lb.NewPool("svc", []config.Backend{{ID: "b1", Addr: srv.URL}})
	b := pool.All()[0]

	c := NewChecker(pool, nil, "/healthz", time.Second)
	ctx := context.Background()

	c.probe(ctx, b)
	c.probe(ctx, b)
	c.probe(ctx, b) // third failure → ejected

	if b.IsHealthy() {
		t.Fatal("backend should be ejected after three 500 responses")
	}
}

// An unreachable backend (connection refused) fails the probe.
func TestChecker_ProbeUnreachableServer(t *testing.T) {
	// Bind then immediately close so the port is unreachable.
	pool := lb.NewPool("svc", []config.Backend{{ID: "b1", Addr: "http://127.0.0.1:1"}})
	b := pool.All()[0]

	c := NewChecker(pool, nil, "/healthz", time.Second)
	ctx := context.Background()

	c.probe(ctx, b)
	c.probe(ctx, b)
	c.probe(ctx, b)

	if b.IsHealthy() {
		t.Fatal("connection-refused backend should be ejected")
	}
}
