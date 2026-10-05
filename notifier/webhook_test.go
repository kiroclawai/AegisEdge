package notifier

import (
	"net"
	"testing"
)

func TestValidateWebhookURL(t *testing.T) {
	cases := []struct {
		name          string
		raw           string
		allowInsecure bool
		allowPrivate  bool
		wantErr       bool
	}{
		{"https public literal ok", "https://8.8.8.8/hook", false, false, false},
		{"http rejected by default", "http://8.8.8.8/xxx", false, false, true},
		{"http allowed with flag", "http://8.8.8.8/xxx", true, false, false},
		{"non-http scheme rejected", "ftp://8.8.8.8/xxx", true, false, true},
		{"empty host rejected", "https://", false, false, true},
		{"loopback literal rejected", "https://127.0.0.1/hook", false, false, true},
		{"loopback allowed with flag", "https://127.0.0.1/hook", false, true, false},
		{"rfc1918 literal rejected", "https://10.1.2.3/hook", false, false, true},
		{"link-local rejected", "https://169.254.169.254/latest", false, false, true},
		// localhost resolves to 127.0.0.1 on any sane resolver.
		{"localhost hostname rejected via DNS", "https://localhost/hook", false, false, true},
		// .invalid never resolves (RFC 2606) — fail-closed.
		{"unresolvable hostname rejected", "https://nonexistent.invalid/hook", false, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateWebhookURL(tc.raw, tc.allowInsecure, tc.allowPrivate)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateWebhookURL(%q) err=%v, wantErr=%v", tc.raw, err, tc.wantErr)
			}
		})
	}
}

func TestIsRestrictedIP(t *testing.T) {
	for _, tc := range []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.5", true},
		{"192.168.1.1", true},
		{"169.254.169.254", true},
		{"224.0.0.1", true},
		{"::1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
	} {
		if got := isRestrictedIP(net.ParseIP(tc.ip)); got != tc.want {
			t.Errorf("isRestrictedIP(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}
