package filter

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

	"aegisedge/logger"
)

// WAFBodyMaxBytes is the maximum request body size the WAF will inspect.
// Bodies longer than this are passed straight through to the upstream
// without regex scanning — an attacker placing the payload past this
// offset would otherwise sail through (Finding 2.3).
//
// 64 KB is large enough for any sane form / JSON payload and small
// enough that buffering it doesn't materially affect the request budget.
// Operators can override at startup via AEGISEDGE_WAF_BODY_MAX_BYTES.
var WAFBodyMaxBytes int64 = 64 * 1024

func init() {
	if s := os.Getenv("AEGISEDGE_WAF_BODY_MAX_BYTES"); s != "" {
		if n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil && n >= 1024 && n <= 4*1024*1024 {
			WAFBodyMaxBytes = n
		}
	}
}

var (
	// SQLi: tautologies, comments, dangerous keywords.
	sqliRegex = regexp.MustCompile(`(?i)(union.*select|insert.*into|drop.*table|delete.*from|update.*set|' or '1'='1|--|/\*|;.*--|exec\(|sp_executesql|information_schema|sysdatabases|waitfor delay)`)

	// XSS: event handlers, javascript pseudo-protocol, script tags.
	xssRegex = regexp.MustCompile(`(?i)(<script|alert\(|onerror=|onload=|onmouseover=|javascript:|eval\(|unescape\(|String\.fromCharCode|<iframe|document\.(cookie|location)|window\.(location|open)|src=.*javascript:)`)

	// Command Injection: shell metacharacters only count when paired with
	// a command context (chained/sh-substituted/piped into a binary), plus
	// bare references to dangerous binaries as whole words. The previous
	// pattern matched single `;`, `|`, `>`, `<` anywhere, which false-
	// positived on ordinary query strings (e.g. `?q=a;b`, `a>b`).
	// Hardened 2026-10-04: require command context around operators.
	cmdInjRegex = regexp.MustCompile(`(?i)(\$\(.*\)|\x60[^\x60]*\x60|;\s*(cat|ls|id|whoami|curl|wget|bash|sh|python|perl|php|nc|ncat|powershell|cmd)\b|\|\s*(cat|ls|id|whoami|curl|wget|bash|sh|nc)\b|&&\s*\w+|\|\|\s*\w+|/bin/(sh|bash)|\b(python|perl|powershell|cmd\.exe)\b|nc\s+-e\b)`)

	// Path Traversal and Sensitive File Access.
	traversal = regexp.MustCompile(`(?i)(\.\./|\.\.\\|/etc/passwd|/windows/system32|boot\.ini|windows/win\.ini|/var/www/html/.*\.env)`)
)

// WAFMiddleware scans the request line, query, and a bounded body
// sample for known-bad patterns. Hardened 2026-09-25 per Finding 2.3:
// previous code used io.ReadFull(buf, 4096) which both blocked until
// EOF and limited inspection to 4 KB; replaced with http.MaxBytesReader
// + io.ReadAll so the goroutine returns quickly and the full bounded
// body is scanned.
func WAFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.RawQuery
		path := r.URL.Path

		var body []byte
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch || r.Method == http.MethodDelete {
			// Cap the body so a streaming attacker cannot OOM the proxy.
			r.Body = http.MaxBytesReader(w, r.Body, WAFBodyMaxBytes)
			var err error
			body, err = io.ReadAll(r.Body)
			if err != nil {
				// MaxBytesError or read error — treat as suspicious.
				logger.Warn("WAF: body read failed", "remote_addr", r.RemoteAddr, "err", err)
				http.Error(w, "Request body too large or unreadable", http.StatusRequestEntityTooLarge)
				return
			}
			// Restore body so the proxy can read it.
			r.Body = io.NopCloser(bytes.NewReader(body))
			if r.ContentLength == -1 {
				r.ContentLength = int64(len(body))
			}
		}

		payloads := []string{query, path, string(body)}
		for _, p := range payloads {
			if p == "" {
				continue
			}
			if sqliRegex.MatchString(p) {
				logger.Warn("Blocked SQLi attempt", "remote_addr", r.RemoteAddr, "payload", truncate(p, 256))
				if MetricsEnabled() {
					BlockedRequests.WithLabelValues("L7", "sqli").Inc()
				}
				http.Error(w, "Malicious request detected", http.StatusBadRequest)
				return
			}
			if xssRegex.MatchString(p) {
				logger.Warn("Blocked XSS attempt", "remote_addr", r.RemoteAddr, "payload", truncate(p, 256))
				if MetricsEnabled() {
					BlockedRequests.WithLabelValues("L7", "xss").Inc()
				}
				http.Error(w, "Malicious request detected", http.StatusBadRequest)
				return
			}
			if cmdInjRegex.MatchString(p) {
				logger.Warn("Blocked Command Injection attempt", "remote_addr", r.RemoteAddr, "payload", truncate(p, 256))
				if MetricsEnabled() {
					BlockedRequests.WithLabelValues("L7", "cmd_injection").Inc()
				}
				http.Error(w, "Malicious request detected", http.StatusBadRequest)
				return
			}
			if traversal.MatchString(p) {
				logger.Warn("Blocked path traversal attempt", "remote_addr", r.RemoteAddr, "payload", truncate(p, 256))
				if MetricsEnabled() {
					BlockedRequests.WithLabelValues("L7", "traversal").Inc()
				}
				http.Error(w, "Malicious request detected", http.StatusBadRequest)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// truncate caps a payload string for log output. Logs that include the
// full matched payload can leak credentials / session tokens when an
// attacker deliberately triggers a block.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...[truncated]"
}
