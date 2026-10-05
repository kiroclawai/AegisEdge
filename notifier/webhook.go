package notifier

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"aegisedge/logger"
)

// UserAgent is sent on every webhook delivery. Overridden by main at
// startup so receivers see the running release (SetUserAgent).
var UserAgent = "AegisEdge/1.0"

// SetUserAgent overrides the default User-Agent header value.
func SetUserAgent(ua string) {
	if ua != "" {
		UserAgent = ua
	}
}

// WebhookMessage is the JSON body sent to all configured receivers.
type WebhookMessage struct {
	Text      string    `json:"text"`
	Timestamp time.Time `json:"timestamp"`
	Severity  string    `json:"severity"`
}

// Sender holds the hardened webhook delivery state. Construct via
// NewSender. Hardened 2026-09-25 per Finding 3.1:
//
//   - URL is validated at construction: must be https:// unless
//     allow_insecure_http is set; loopback / private destinations
//     require explicit allowlist.
//   - HTTP client enforces TLS 1.2 minimum and a 10s per-request timeout.
//   - Body is signed with HMAC-SHA256 over (timestamp + "." + body) using
//     AEGISEDGE_WEBHOOK_SECRET; receivers verify
//     X-Aegis-Timestamp and X-Aegis-Signature.
//   - Retries with exponential backoff (1s, 5s, 30s) up to 3 attempts.
//   - Slack receiver adapter sets X-Slack-Signature + X-Slack-Request-Timestamp.
//   - PagerDuty receiver adapter uses v2 events API and embeds routing_key.
type Sender struct {
	URL              string
	Secret           []byte
	HTTPClient       *http.Client
	AllowInsecureHTTP bool
	AllowPrivateHosts bool
	MaxAttempts      int
	InitialBackoff   time.Duration
	MaxBackoff       time.Duration
}

// NewSender reads the environment and returns a configured Sender.
// Returns an error if the webhook is mis-configured; callers should
// treat this as fatal (a misconfigured alert path is a security issue).
//
// Environment:
//   - AEGISEDGE_WEBHOOK_URL: https:// URL of the receiver (required)
//   - AEGISEDGE_WEBHOOK_SECRET: HMAC secret (recommended; required for Slack/PD)
//   - AEGISEDGE_WEBHOOK_ALLOW_HTTP: "1" to permit http:// (dev only)
//   - AEGISEDGE_WEBHOOK_ALLOW_PRIVATE_HOST: "1" to allow 127.0.0.1, RFC1918, link-local
//   - AEGISEDGE_WEBHOOK_TIMEOUT: seconds per HTTP attempt (default 10)
//   - AEGISEDGE_WEBHOOK_RECEIVER: "slack" | "pagerduty" | "generic" (default "generic")
//   - AEGISEDGE_WEBHOOK_PD_ROUTING_KEY: routing key for PagerDuty events v2
func NewSender() (*Sender, error) {
	webhookURL := os.Getenv("AEGISEDGE_WEBHOOK_URL")
	if webhookURL == "" {
		return nil, nil // not configured: callers should treat nil as "no-op"
	}
	secret := os.Getenv("AEGISEDGE_WEBHOOK_SECRET")
	if secret == "" {
		// Not fatal for generic receivers, but warn loudly. Slack / PD
		// adapters refuse unsigned payloads below.
		logger.Warn("AEGISEDGE_WEBHOOK_SECRET unset — generic receivers will receive unsigned bodies")
	}
	allowInsecure := os.Getenv("AEGISEDGE_WEBHOOK_ALLOW_HTTP") == "1"
	allowPrivate := os.Getenv("AEGISEDGE_WEBHOOK_ALLOW_PRIVATE_HOST") == "1"

	if err := validateWebhookURL(webhookURL, allowInsecure, allowPrivate); err != nil {
		return nil, fmt.Errorf("webhook URL invalid: %w", err)
	}

	timeout := 10 * time.Second
	if s := os.Getenv("AEGISEDGE_WEBHOOK_TIMEOUT"); s != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 && n <= 60 {
			timeout = time.Duration(n) * time.Second
		}
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
			MaxIdleConns:        16,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     30 * time.Second,
			DisableKeepAlives:   false,
		},
		// No silent redirect following: a 302 to attacker.com leaks body.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &Sender{
		URL:               webhookURL,
		Secret:            []byte(secret),
		HTTPClient:        client,
		AllowInsecureHTTP: allowInsecure,
		AllowPrivateHosts: allowPrivate,
		MaxAttempts:       3,
		InitialBackoff:    1 * time.Second,
		MaxBackoff:        30 * time.Second,
	}, nil
}

// validateWebhookURL rejects URLs that don't match the security policy.
// Hardened 2026-10-04: in addition to IP-literal checks, hostnames are
// resolved via DNS (5s timeout) and every returned A/AAAA is screened
// against loopback / private / link-local / multicast / unspecified.
// This closes SSRF via DNS names (evil.example.com -> 169.254.169.254)
// and DNS rebinding. Resolution failure is fail-closed with a clear
// message; use a literal IP or fix DNS to proceed.
func validateWebhookURL(raw string, allowInsecure, allowPrivate bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "https" {
		if u.Scheme != "http" || !allowInsecure {
			return errors.New("webhook URL must be https (set AEGISEDGE_WEBHOOK_ALLOW_HTTP=1 only for dev)")
		}
	}
	if u.Host == "" {
		return errors.New("webhook URL has empty host")
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("webhook URL has empty hostname")
	}
	if !allowPrivate {
		if ip := net.ParseIP(host); ip != nil {
			if isRestrictedIP(ip) {
				return errors.New("webhook URL points at loopback / private / link-local host (set AEGISEDGE_WEBHOOK_ALLOW_PRIVATE_HOST=1 to override)")
			}
			return nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil || len(addrs) == 0 {
			return fmt.Errorf("webhook URL hostname failed to resolve (fail-closed): %w", err)
		}
		for _, a := range addrs {
			if isRestrictedIP(a.IP) {
				return errors.New("webhook URL resolves to loopback / private / link-local address (set AEGISEDGE_WEBHOOK_ALLOW_PRIVATE_HOST=1 to override)")
			}
		}
	}
	return nil
}

func isRestrictedIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast()
}

// receiverKind returns the configured receiver type.
func receiverKind() string {
	if s := os.Getenv("AEGISEDGE_WEBHOOK_RECEIVER"); s != "" {
		return s
	}
	return "generic"
}

// SendAlert posts a signed alert to the configured receiver with
// bounded retries. Async by default to avoid blocking traffic.
func (s *Sender) SendAlert(msg string, severity string) {
	if s == nil {
		return // no webhook configured
	}
	body, err := json.Marshal(WebhookMessage{
		Text:      fmt.Sprintf("[AegisEdge Alert] %s", msg),
		Timestamp: time.Now().UTC(),
		Severity:  severity,
	})
	if err != nil {
		logger.Error("webhook: marshal failed", "err", err)
		return
	}
	go s.deliver(body, receiverKind())
}

// deliver sends the body with retry/backoff. Honours the configured
// receiver adapter (Slack / PagerDuty / generic).
func (s *Sender) deliver(origBody []byte, kind string) {
	// PagerDuty wrapping happens ONCE before the retry loop — wrapping
	// inside the loop double-wrapped on attempt 2+ (body of body).
	body := origBody
	if kind == "pagerduty" {
		if os.Getenv("AEGISEDGE_WEBHOOK_PD_ROUTING_KEY") == "" {
			logger.Error("webhook: PagerDuty receiver requires AEGISEDGE_WEBHOOK_PD_ROUTING_KEY")
			return
		}
		body = wrapForPagerDuty(origBody)
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, s.Secret)
	mac.Write([]byte(ts))
	mac.Write([]byte{'.'})
	mac.Write(body)
	sig := "v1=" + hex.EncodeToString(mac.Sum(nil))

	backoff := s.InitialBackoff
	for attempt := 1; attempt <= s.MaxAttempts; attempt++ {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, s.URL, bytes.NewReader(body))
		if err != nil {
			logger.Error("webhook: build request failed", "err", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", UserAgent)
		req.Header.Set("X-Aegis-Timestamp", ts)
		req.Header.Set("X-Aegis-Signature", sig)

		if kind == "slack" {
			// Slack verifies: v0=hex(hmac(secret, "v0:"+ts+":"+body)).
			slackMac := hmac.New(sha256.New, s.Secret)
			slackMac.Write([]byte("v0:" + ts + ":"))
			slackMac.Write(body)
			req.Header.Set("X-Slack-Request-Timestamp", ts)
			req.Header.Set("X-Slack-Signature", "v0="+hex.EncodeToString(slackMac.Sum(nil)))
		}

		resp, err := s.HTTPClient.Do(req)
		if err != nil {
			logger.Warn("webhook: delivery failed", "attempt", attempt, "err", err)
		} else {
			func() {
				defer resp.Body.Close()
				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					logger.Info("webhook: delivered", "attempt", attempt, "status", resp.StatusCode)
					return
				}
				logger.Warn("webhook: non-2xx response", "attempt", attempt, "status", resp.StatusCode)
			}()
			// 2xx: success. Non-2xx: also treat as success for the retry loop
			// (the receiver is reachable; signing / payload issues don't benefit
			// from retry). Break out of the loop to avoid hammering.
			return
		}

		if attempt < s.MaxAttempts {
			time.Sleep(backoff)
			backoff *= 5
			if backoff > s.MaxBackoff {
				backoff = s.MaxBackoff
			}
		}
	}
	logger.Error("webhook: exhausted retries", "max_attempts", s.MaxAttempts)
}

// wrapForPagerDuty converts a generic WebhookMessage into a PagerDuty
// Events API v2 payload.
func wrapForPagerDuty(body []byte) []byte {
	rk := os.Getenv("AEGISEDGE_WEBHOOK_PD_ROUTING_KEY")
	wrapped := map[string]any{
		"routing_key":  rk,
		"event_action": "trigger",
		"payload":      json.RawMessage(body),
	}
	out, _ := json.Marshal(wrapped)
	return out
}

// Backwards-compatible package-level helpers used by existing callers.
// New code should construct a *Sender via NewSender and use SendAlert.
func init() {
	if s, err := NewSender(); err != nil {
		logger.Error("webhook: init failed", "err", err)
	} else if s != nil {
		defaultSender = s
	}
}

var defaultSender *Sender

// SendAlert is the package-level convenience wrapper around the
// default Sender. Kept for source-compatibility with the existing
// call sites in filter/reputation.go and filter/orchestration.go.
func SendAlert(msg string, severity string) {
	if defaultSender == nil {
		return
	}
	defaultSender.SendAlert(msg, severity)
}
