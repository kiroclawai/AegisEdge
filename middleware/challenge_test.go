package middleware

import (
	"fmt"
	"os"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	// getSecretKey is fail-closed via sync.Once; guarantee a test secret
	// when the environment does not provide one (CI sets the real one).
	if os.Getenv("AEGISEDGE_SECRET") == "" {
		os.Setenv("AEGISEDGE_SECRET", "test-only-secret-32bytes-minimum!")
	}
	os.Exit(m.Run())
}

func TestVerifyCookieRoundTrip(t *testing.T) {
	ip := "203.0.113.7"
	ts := fmt.Sprintf("%d", time.Now().Unix())
	token := ts + "." + generateSignature(ts, ip)
	if !verifyCookie(token, ip) {
		t.Fatal("freshly minted token should verify")
	}
	// IP binding: same token from another address must fail.
	if verifyCookie(token, "198.51.100.9") {
		t.Fatal("token must be bound to the issuing IP")
	}
}

func TestVerifyCookieRejects(t *testing.T) {
	ip := "203.0.113.7"
	ts := fmt.Sprintf("%d", time.Now().Unix())
	sigFor := func(s string) string { return s + "." + generateSignature(s, ip) }
	expiredTS := fmt.Sprintf("%d", time.Now().Unix()-CookieExpiry-10)
	futureTS := fmt.Sprintf("%d", time.Now().Unix()+3600)
	cases := []struct {
		name  string
		token string
	}{
		{"malformed", "not-a-token"},
		{"three parts", "a.b.c"},
		// Wrong HMAC for the claimed timestamp.
		{"tampered sig", ts + ".deadbeef"},
		// Correct HMAC but unparseable / out-of-window timestamps,
		// exercising the ParseInt + skew checks past the HMAC gate.
		{"non-numeric ts", sigFor("abc")},
		{"negative ts", sigFor("-123")},
		{"expired", sigFor(expiredTS)},
		{"far future", sigFor(futureTS)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if verifyCookie(tc.token, ip) {
				t.Errorf("token %q should be rejected", tc.token)
			}
		})
	}
}
