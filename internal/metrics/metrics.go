// Package metrics exposes Prometheus counters/gauges/histograms.
//
// The label set is intentionally small so cardinality stays bounded:
//   - decision reasons are a closed enum defined in package auth/proxy
//   - upstream id is bounded by the config's backend list
package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	RequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gateway_requests_total",
		Help: "Requests received by the gateway, labelled by final decision.",
	}, []string{"route", "decision", "reason"})

	UpstreamRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gateway_upstream_requests_total",
		Help: "Requests forwarded to upstream backends.",
	}, []string{"service", "backend", "code"})

	UpstreamLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "gateway_upstream_latency_seconds",
		Help:    "Upstream call latency.",
		Buckets: prometheus.DefBuckets,
	}, []string{"service", "backend"})

	BackendHealthy = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "gateway_backend_healthy",
		Help: "1 if the backend is currently in the healthy pool, else 0.",
	}, []string{"service", "backend"})

	AuthFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gateway_auth_failures_total",
		Help: "Authentication/authorization failures by reason.",
	}, []string{"reason"})
)

func Handler() http.Handler { return promhttp.Handler() }

// Observe records upstream latency and the response code together so both
// series always move in lock-step.
func Observe(service, backend string, code int, start time.Time) {
	UpstreamRequestsTotal.WithLabelValues(service, backend, strconv.Itoa(code)).Inc()
	UpstreamLatency.WithLabelValues(service, backend).Observe(time.Since(start).Seconds())
}
