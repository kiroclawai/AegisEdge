package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"aegisedge/filter"
	"aegisedge/logger"
)

const (
	ChallengeCookieName = "ae_clearance"
	CookieExpiry        = 3600 // 1 hour in seconds
)

var (
	secretOnce sync.Once
	secretKey  []byte
)

// getSecretKey loads AEGISEDGE_SECRET on first use (fail-closed).
// Lazy so package import / unit tests that never touch challenges do not panic.
func getSecretKey() []byte {
	secretOnce.Do(func() {
		s := os.Getenv("AEGISEDGE_SECRET")
		if s == "" {
			panic("AEGISEDGE_SECRET is required; generate one with `openssl rand -hex 32`")
		}
		if len(s) < 32 {
			panic("AEGISEDGE_SECRET must be at least 32 bytes; generate one with `openssl rand -hex 32`")
		}
		secretKey = []byte(s)
	})
	return secretKey
}

func generateSignature(val, ip string) string {
	h := hmac.New(sha256.New, getSecretKey())
	h.Write([]byte(val + ":" + ip))
	return hex.EncodeToString(h.Sum(nil))
}

func ProgressiveChallenge(next http.Handler, rep *filter.ReputationManager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := GetRealIP(r)

		cookie, err := r.Cookie(ChallengeCookieName)
		if err == nil && verifyCookie(cookie.Value, host) {
			next.ServeHTTP(w, r)
			return
		}

		if token := r.URL.Query().Get("ae_token"); token != "" {
			if verifyCookie(token, host) {
				if rep != nil {
					rep.Reward(host)
				}
				http.SetCookie(w, &http.Cookie{
					Name:     ChallengeCookieName,
					Value:    token,
					Path:     "/",
					MaxAge:   CookieExpiry,
					SameSite: http.SameSiteStrictMode,
					HttpOnly: true,
					Secure:   r.TLS != nil,
				})
				target := r.URL.Path
				if r.URL.RawQuery != "" {
					q := r.URL.Query()
					q.Del("ae_token")
					if len(q) > 0 {
						target += "?" + q.Encode()
					}
				}
				http.Redirect(w, r, target, http.StatusFound)
				return
			}
		}

		logger.Info("Serving JS challenge (no valid clearance)", "remote_addr", r.RemoteAddr, "path", r.URL.Path)
		serveChallenge(w, r, host)
	})
}

func serveChallenge(w http.ResponseWriter, r *http.Request, ip string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusServiceUnavailable)

	ts := fmt.Sprintf("%d", time.Now().Unix())
	sig := generateSignature(ts, ip)
	token := ts + "." + sig

	// Hardened 2026-10-04: encode the redirect target as a Go-quoted
	// string literal (safe in JS double-quoted context). html.EscapeString
	// is the wrong context inside <script> (entities are not decoded
	// there); strconv.Quote escapes quotes, backslashes and control
	// characters so a crafted path cannot break out of the string.
	redirectPath := r.URL.Path
	if redirectPath == "" {
		redirectPath = "/"
	}
	jsTarget := strconv.Quote(redirectPath + "?ae_token=" + token)

	htmlBody := `<!DOCTYPE html>
<html>
  <head>
    <title>AegisEdge — Checking your browser</title>
    <meta charset="utf-8">
    <style>
      body { font-family: sans-serif; display:flex; align-items:center; justify-content:center; height:100vh; margin:0; background:#0d1117; color:#cdd9e5; }
      .box { text-align:center; }
      .spinner { width:40px; height:40px; border:4px solid #30363d; border-top-color:#58a6ff; border-radius:50%; animation:spin 0.8s linear infinite; margin:1rem auto; }
      @keyframes spin { to { transform: rotate(360deg); } }
    </style>
  </head>
  <body>
    <div class="box">
      <div class="spinner"></div>
      <h2>Checking your browser&hellip;</h2>
      <p>AegisEdge Security &mdash; one moment please.</p>
      <script>
        setTimeout(function() {
          window.location.href = ` + jsTarget + `;
        }, 2000);
      </script>
    </div>
  </body>
</html>`
	fmt.Fprint(w, htmlBody)
}

func verifyCookie(val, ip string) bool {
	parts := strings.Split(val, ".")
	if len(parts) != 2 {
		return false
	}

	tsStr, providedSig := parts[0], parts[1]

	// Constant-time HMAC comparison.
	expectedSig := generateSignature(tsStr, ip)
	if !hmac.Equal([]byte(providedSig), []byte(expectedSig)) {
		logger.Warn("Invalid challenge cookie signature or IP mismatch", "client_ip", ip)
		return false
	}

	// Hardened 2026-09-25 per Finding 2.5: strict integer parsing.
	// Previous code used fmt.Sscanf which silently accepted "abc",
	// "+1234567890", "-9223372036854775808" and produced surprising
	// values; now we reject anything that is not a base-10 integer in
	// the int64 range.
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		logger.Warn("Invalid challenge timestamp", "timestamp", tsStr)
		return false
	}
	now := time.Now().Unix()
	if now > ts+CookieExpiry {
		logger.Warn("Expired challenge cookie", "timestamp", ts)
		return false
	}
	if ts > now+300 {
		logger.Warn("Future challenge timestamp (clock-skew or forgery)", "timestamp", ts)
		return false
	}

	return true
}
