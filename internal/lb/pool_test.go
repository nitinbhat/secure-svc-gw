package lb

import (
	"sync"
	"testing"
	"time"

	"github.com/nibhat/secure-svc-gw/internal/config"
)

func newTestPool() *Pool {
	return NewPool("test", []config.Backend{
		{ID: "a", Addr: "https://a"},
		{ID: "b", Addr: "https://b"},
		{ID: "c", Addr: "https://c"},
	})
}

func TestPick_AllHealthy(t *testing.T) {
	p := newTestPool()
	for i := 0; i < 20; i++ {
		if p.Pick() == nil {
			t.Fatal("expected non-nil pick")
		}
	}
}

func TestPick_SkipsUnhealthy(t *testing.T) {
	p := newTestPool()
	for _, b := range p.All() {
		if b.ID != "c" {
			b.SetHealthy(false)
		}
	}
	for i := 0; i < 10; i++ {
		got := p.Pick()
		if got == nil || got.ID != "c" {
			t.Fatalf("want backend c, got %+v", got)
		}
	}
}

func TestPick_NoneHealthy(t *testing.T) {
	p := newTestPool()
	for _, b := range p.All() {
		b.SetHealthy(false)
	}
	if p.Pick() != nil {
		t.Fatal("expected nil when nothing healthy")
	}
}

func TestP2CPrefersLowerScore(t *testing.T) {
	// Only two healthy backends -> P2C degenerates to "pick the lower".
	p := NewPool("s", []config.Backend{{ID: "hot", Addr: "h"}, {ID: "cold", Addr: "c"}})
	// Simulate: hot has taken 10ms average and is doing 5 things; cold is idle.
	for _, b := range p.All() {
		if b.ID == "hot" {
			b.RecordLatency(10_000_000) // 10ms in ns
			for i := 0; i < 5; i++ {
				b.Acquire()
			}
		}
	}
	hits := map[string]int{}
	for i := 0; i < 500; i++ {
		hits[p.Pick().ID]++
	}
	if hits["cold"] <= hits["hot"] {
		t.Fatalf("expected cold to dominate hot; got %+v", hits)
	}
}

// ---------------------------------------------------------------------------
// P2C distribution: A=10ms B=100ms C=15ms D=unhealthy → 1000 requests.
// A and C should capture >80% of traffic; D must never be chosen.
// ---------------------------------------------------------------------------

func TestP2C_DistributionFavorsLowLatency(t *testing.T) {
	p := NewPool("svc", []config.Backend{
		{ID: "a", Addr: "http://a"},
		{ID: "b", Addr: "http://b"},
		{ID: "c", Addr: "http://c"},
		{ID: "d", Addr: "http://d"},
	})
	for _, b := range p.All() {
		switch b.ID {
		case "a":
			b.RecordLatency(10 * time.Millisecond)
		case "b":
			b.RecordLatency(100 * time.Millisecond)
		case "c":
			b.RecordLatency(15 * time.Millisecond)
		case "d":
			b.SetHealthy(false)
		}
	}

	const n = 1000
	hits := map[string]int{}
	for i := 0; i < n; i++ {
		got := p.Pick()
		if got == nil {
			t.Fatal("nil pick unexpected")
		}
		if got.ID == "d" {
			t.Fatal("unhealthy backend d must never be picked")
		}
		hits[got.ID]++
	}

	good := hits["a"] + hits["c"]
	if good < n*80/100 {
		t.Errorf("A+C should get >80%% of traffic, got %d/%d; distribution: %v", good, n, hits)
	}
}

// ---------------------------------------------------------------------------
// Inflight weighting: equal latency, busy has 50 in-flight → idle dominates.
// ---------------------------------------------------------------------------

func TestP2C_InflightWeighting(t *testing.T) {
	p := NewPool("svc", []config.Backend{
		{ID: "busy", Addr: "http://busy"},
		{ID: "idle", Addr: "http://idle"},
	})
	for _, b := range p.All() {
		b.RecordLatency(10 * time.Millisecond)
		if b.ID == "busy" {
			for i := 0; i < 50; i++ {
				b.Acquire()
			}
		}
	}

	hits := map[string]int{}
	for i := 0; i < 200; i++ {
		hits[p.Pick().ID]++
	}
	if hits["idle"] <= hits["busy"] {
		t.Errorf("idle should dominate busy backend; got %v", hits)
	}
}

// ---------------------------------------------------------------------------
// EWMA is reset when a backend transitions unhealthy → healthy.
// Without the reset a stale high-latency EWMA would starve the recovered peer.
// ---------------------------------------------------------------------------

func TestBackend_EWMAReset(t *testing.T) {
	b := &Backend{}
	b.SetHealthy(true)
	b.RecordLatency(100 * time.Millisecond) // build up a high EWMA

	// Eject, then restore.
	b.SetHealthy(false)
	b.SetHealthy(true)

	// score() treats ewmaMs=0 as 1; with inflight=0 → score = 1.0
	if got := b.score(); got != 1.0 {
		t.Errorf("expected score 1.0 after EWMA reset, got %f", got)
	}
}

// ---------------------------------------------------------------------------
// Recovering backend is eventually selected after two consecutive successes.
// ---------------------------------------------------------------------------

func TestPool_RecoveringBackendSelected(t *testing.T) {
	p := NewPool("svc", []config.Backend{
		{ID: "stable", Addr: "http://stable"},
		{ID: "flaky", Addr: "http://flaky"},
	})
	// Eject flaky.
	for _, b := range p.All() {
		if b.ID == "flaky" {
			b.SetHealthy(false)
		}
	}
	// Restore it.
	for _, b := range p.All() {
		if b.ID == "flaky" {
			b.SetHealthy(true)
		}
	}
	// Both are now healthy; flaky must appear in some picks.
	hits := map[string]int{}
	for i := 0; i < 200; i++ {
		hits[p.Pick().ID]++
	}
	if hits["flaky"] == 0 {
		t.Error("recovered backend should eventually be selected")
	}
}

// ---------------------------------------------------------------------------
// SafeScore edge cases.
// ---------------------------------------------------------------------------

func TestSafeScore(t *testing.T) {
	// ewma=0 → treated as 1, inflight=0 → score = 1*1 = 1
	if got := SafeScore(0, 0); got != 1.0 {
		t.Errorf("SafeScore(0,0) = %f, want 1.0", got)
	}
	// ewma=10ms, inflight=5 → score = 10*6 = 60
	if got := SafeScore(10, 5); got != 60.0 {
		t.Errorf("SafeScore(10,5) = %f, want 60.0", got)
	}
}

// ---------------------------------------------------------------------------
// Race test: concurrent Pick + SetHealthy must not panic.
// Run with: go test -race ./internal/lb/...
// ---------------------------------------------------------------------------

func TestPool_Race(t *testing.T) {
	p := newTestPool()

	var wg sync.WaitGroup
	done := make(chan struct{})

	// Writer: flip health states rapidly.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			for _, b := range p.All() {
				b.SetHealthy(i%2 == 0)
			}
		}
		close(done)
	}()

	// Reader: keep picking concurrently.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				p.Pick() // nil is fine when all are unhealthy
			}
		}
	}()

	wg.Wait()
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

// BenchmarkPool_Pick measures P2C: healthy snapshot → 2 random picks → EWMA compare.
// Run: go test -bench=BenchmarkPool_Pick -benchmem ./internal/lb/...
func BenchmarkPool_Pick(b *testing.B) {
	p := NewPool("svc", []config.Backend{
		{ID: "a", Addr: "http://a"},
		{ID: "b", Addr: "http://b"},
		{ID: "c", Addr: "http://c"},
		{ID: "d", Addr: "http://d"},
	})
	for _, bk := range p.All() {
		bk.RecordLatency(10 * time.Millisecond)
		if bk.ID == "d" {
			bk.SetHealthy(false)
		}
	}
	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			p.Pick()
		}
	})
}
