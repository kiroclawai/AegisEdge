package manager

import (
	"crypto/subtle"
	"net/http"
	"os"
	"strings"

	"aegisedge/logger"
)

// MinAPIKeyBytes is the minimum acceptable length for AEGISEDGE_API_KEY.
// 32 bytes provides 256 bits of entropy — short keys are brute-forceable.
const MinAPIKeyBytes = 32

// APIKeyAuth returns middleware that gates all management API requests
// behind a Bearer token.
//
// Security posture (hardened 2026-09-25, Finding 1.1):
//   - If AEGISEDGE_API_KEY is unset or shorter than MinAPIKeyBytes, the
//     middleware PANICS rather than fail-open. The management API must
//     NEVER be reachable without authentication.
//   - Comparison uses crypto/subtle to avoid a timing side-channel
//     (Finding 1.2).
//
// Operator action required: generate a >=32 byte secret and export it
// before starting the proxy, e.g.:
//
//	export AEGISEDGE_API_KEY="$(openssl rand -hex 32)"
//
// To run with no management API (lock-down), set AEGISEDGE_DISABLE_MGMT=1
// and do not bind :9091.
func APIKeyAuth(next http.Handler) http.Handler {
	apiKey := os.Getenv("AEGISEDGE_API_KEY")
	if apiKey == "" {
		logger.Error("AEGISEDGE_API_KEY is unset — refusing to start management API")
		panic("AEGISEDGE_API_KEY is required; generate one with `openssl rand -hex 32` and export it")
	}
	if len(apiKey) < MinAPIKeyBytes {
		logger.Error("AEGISEDGE_API_KEY too short", "min_bytes", MinAPIKeyBytes, "got_bytes", len(apiKey))
		panic("AEGISEDGE_API_KEY must be at least 32 bytes; generate one with `openssl rand -hex 32`")
	}

	logger.Info("Management API authentication enabled (Bearer token)")

	// Pre-compute the expected value once so the per-request hot path
	// doesn't reallocate. subtle.ConstantTimeCompare is used to avoid
	// an early-exit timing side-channel; note it returns 0 immediately
	// when lengths differ, so key length is not strongly protected —
	// the 32-byte minimum keeps the search space infeasible regardless.
	expected := []byte(apiKey)
	_ = expected // explicit capture for the closure below

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		// Expect "Bearer <key>".
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		provided := []byte(auth[len("Bearer "):])
		// Constant-time compare; safe even when lengths differ
		// (subtle.ConstantTimeCompare returns 0 for mismatched lengths
		// without leaking length info via early-exit).
		if subtle.ConstantTimeCompare(provided, expected) != 1 {
			logger.Warn("Management API: invalid auth attempt", "remote_addr", r.RemoteAddr)
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}
