// Package logging returns a structured JSON slog logger.
//
// Every allow/deny/route decision is logged as a single JSON line with a
// stable set of fields so an operator can grep/aggregate them:
//
//   decision   : "allow" | "deny" | "route"
//   reason     : short machine-readable code (e.g. "expired", "replay",
//                "no_scope", "backend_unhealthy", "spoofed_backend")
//   route      : matched route prefix
//   sub / kid  : JWT subject and key id (when present)
//   upstream   : chosen backend id
//   latency_ms : upstream call duration
package logging

import (
	"log/slog"
	"os"
)

func New() *slog.Logger {
	level := slog.LevelInfo
	if os.Getenv("GATEWAY_DEBUG") == "1" {
		level = slog.LevelDebug
	}
	h := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	return slog.New(h).With("service", "gateway")
}
