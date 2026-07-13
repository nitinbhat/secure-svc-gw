package proxy

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/nibhat/secure-svc-gw/internal/auth"
	"github.com/nibhat/secure-svc-gw/internal/config"
	"github.com/nibhat/secure-svc-gw/internal/lb"
	"github.com/nibhat/secure-svc-gw/internal/metrics"
)

// Handler is the gateway's single HTTP handler. It:
//
//  1. matches the URL path to a configured route
//  2. authenticates the caller (JWT)
//  3. authorizes the caller against the route's required scope
//  4. picks a healthy backend via P2C
//  5. forwards over mTLS, records latency, and retries once on a network
//     error (but never on a 4xx -- that is a real answer from the backend)
//
// Every branch emits ONE structured log line with a `decision` field so
// the demo scripts can grep it out.
type Handler struct {
	routes   []routeEntry
	verifier *auth.Verifier
	pools    map[string]*lb.Pool
	clients  map[string]*http.Client // one client per service (holds mTLS cfg)
}

type routeEntry struct {
	prefix        string
	service       string
	requiredScope string
}

func NewHandler(cfg *config.Config, pools map[string]*lb.Pool, clients map[string]*http.Client, verifier *auth.Verifier) *Handler {
	routes := make([]routeEntry, 0, len(cfg.Routes))
	for _, r := range cfg.Routes {
		routes = append(routes, routeEntry{
			prefix:        r.Prefix,
			service:       r.Service,
			requiredScope: r.RequiredScope,
		})
	}
	return &Handler{routes: routes, verifier: verifier, pools: pools, clients: clients}
}

func newRequestID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rid := newRequestID()
	w.Header().Set("X-Request-Id", rid)

	route, ok := h.match(r.URL.Path)
	if !ok {
		metrics.RequestsTotal.WithLabelValues("none", "deny", "no_route").Inc()
		slog.Info("request rejected",
			"request_id", rid, "decision", "deny", "reason", "no_route",
			"path", r.URL.Path, "method", r.Method,
		)
		http.Error(w, "no route", http.StatusNotFound)
		return
	}

	// --- authenticate ---
	tok := extractBearer(r)
	if tok == "" {
		h.denyAuth(w, rid, route, "", "", auth.ReasonNoToken)
		return
	}
	claims, sub, aerr := h.verifier.Verify(tok)
	if aerr != nil {
		kid := "unknown"
		if claims != nil {
			kid = claims.Sub
		}
		h.denyAuth(w, rid, route, sub, kid, aerr.Reason)
		return
	}
	// --- authorize ---
	if !auth.HasScope(claims, route.requiredScope) {
		h.denyAuth(w, rid, route, sub, claims.Jti, auth.ReasonMissingScope)
		return
	}

	// --- pick backend ---
	pool := h.pools[route.service]
	backend := pool.Pick()
	if backend == nil {
		metrics.RequestsTotal.WithLabelValues(route.prefix, "deny", "no_healthy_backend").Inc()
		slog.Error("no healthy backend",
			"request_id", rid, "decision", "deny", "reason", "no_healthy_backend",
			"route", route.prefix, "target_service", route.service, "sub", sub,
		)
		http.Error(w, "no healthy backend", http.StatusServiceUnavailable)
		return
	}

	// --- forward with one retry on network error ---
	code, upstreamID, err := h.forward(r.Context(), r, w, route, pool, backend, rid, sub)
	if err != nil && isRetryable(err) {
		if alt := pool.Pick(); alt != nil && alt.ID != backend.ID {
			slog.Warn("retrying on alt backend",
				"request_id", rid, "decision", "route", "reason", "retry",
				"route", route.prefix, "prev_upstream", backend.ID, "upstream", alt.ID,
				"err", err.Error(),
			)
			code, upstreamID, err = h.forward(r.Context(), r, w, route, pool, alt, rid, sub)
		}
	}
	if err != nil {
		metrics.RequestsTotal.WithLabelValues(route.prefix, "deny", "upstream_error").Inc()
		slog.Error("upstream error",
			"request_id", rid, "decision", "deny", "reason", "upstream_error",
			"route", route.prefix, "upstream", upstreamID, "err", err.Error(),
		)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	metrics.RequestsTotal.WithLabelValues(route.prefix, "allow", "ok").Inc()
	slog.Info("request forwarded",
		"request_id", rid, "decision", "allow", "reason", "ok",
		"route", route.prefix, "target_service", route.service,
		"upstream", upstreamID, "sub", sub, "jti", claims.Jti, "code", code,
	)
}

func (h *Handler) match(path string) (routeEntry, bool) {
	for _, r := range h.routes {
		if strings.HasPrefix(path, r.prefix) {
			return r, true
		}
	}
	return routeEntry{}, false
}

func (h *Handler) denyAuth(w http.ResponseWriter, rid string, route routeEntry, sub, kid, reason string) {
	metrics.RequestsTotal.WithLabelValues(route.prefix, "deny", reason).Inc()
	metrics.AuthFailures.WithLabelValues(reason).Inc()
	slog.Warn("request denied",
		"request_id", rid, "decision", "deny", "reason", reason,
		"route", route.prefix, "sub", sub, "kid", kid,
	)
	status := http.StatusUnauthorized
	if reason == auth.ReasonMissingScope {
		status = http.StatusForbidden
	}
	http.Error(w, reason, status)
}

// forward proxies a single request to `b` using the mTLS client for the
// service. It returns the upstream status code (or 0 on transport error),
// the backend ID actually used, and any error.
func (h *Handler) forward(
	ctx context.Context,
	r *http.Request,
	w http.ResponseWriter,
	route routeEntry,
	pool *lb.Pool,
	b *lb.Backend,
	rid, sub string,
) (int, string, error) {
	b.Acquire()
	defer b.Release()

	// Strip the route prefix so the backend sees a clean URL. Backends
	// don't know they're behind a gateway.
	target := b.Addr + strings.TrimPrefix(r.URL.Path, route.prefix)
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	req, err := http.NewRequestWithContext(ctx, r.Method, target, r.Body)
	if err != nil {
		return 0, b.ID, err
	}
	copyHeaders(r.Header, req.Header)
	// Do NOT forward the client's Authorization -- the backend trusts us
	// via mTLS, not JWT. Instead we forward identity as headers.
	req.Header.Del("Authorization")
	req.Header.Set("X-Forwarded-Sub", sub)
	req.Header.Set("X-Request-Id", rid)

	start := time.Now()
	resp, err := h.clients[route.service].Do(req)
	elapsed := time.Since(start)
	b.RecordLatency(elapsed)

	if err != nil {
		metrics.Observe(route.service, b.ID, 0, start)
		return 0, b.ID, err
	}
	defer resp.Body.Close()
	metrics.Observe(route.service, b.ID, resp.StatusCode, start)

	copyHeaders(resp.Header, w.Header())
	w.Header().Set("X-Upstream", b.ID)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
	return resp.StatusCode, b.ID, nil
}

func copyHeaders(src, dst http.Header) {
	for k, vs := range src {
		// Hop-by-hop headers per RFC 7230.
		switch strings.ToLower(k) {
		case "connection", "keep-alive", "proxy-authenticate",
			"proxy-authorization", "te", "trailer", "transfer-encoding",
			"upgrade":
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func extractBearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if len(h) <= len(p) || !strings.EqualFold(h[:len(p)], p) {
		return ""
	}
	return strings.TrimSpace(h[len(p):])
}

// isRetryable returns true only for transport-level errors -- never for a
// real HTTP response. Retrying a 4xx would just double the work.
func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	// net.OpError, tls.RecordHeaderError, io.EOF on write, etc. all satisfy
	// this check via the Error() string being non-empty; we intentionally
	// keep the predicate coarse.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	return true
}

// NewBackendClient returns an *http.Client wired to the given mTLS config,
// with sensible timeouts for a service-mesh hop.
func NewBackendClient(tlsCfg *tls.Config) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:       tlsCfg,
			MaxIdleConnsPerHost:   16,
			IdleConnTimeout:       60 * time.Second,
			ResponseHeaderTimeout: 8 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}
