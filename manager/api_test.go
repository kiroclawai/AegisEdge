package manager

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"aegisedge/store"
)

func testAPI() *ManagementAPI {
	return NewManagementAPI(
		store.NewLocalStore(),
		NewLiveToggles(true, true, true, true, true),
		nil, // ProxyWatcher not needed for block/config paths
	)
}

func serveAPI(api *ManagementAPI, method, target, body string) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	api.ServeHTTP(mux)
	var rdr *strings.Reader
	if body == "" {
		rdr = strings.NewReader("")
	} else {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, rdr)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

func TestHandleBlockPostValidation(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int
	}{
		{"valid temp", `{"ip":"9.9.9.9","duration":"1h"}`, http.StatusCreated},
		{"valid default duration", `{"ip":"9.9.9.10"}`, http.StatusCreated},
		{"valid permanent", `{"ip":"9.9.9.11","duration":"permanent"}`, http.StatusCreated},
		{"garbage ip", `{"ip":"not-an-ip","duration":"1h"}`, http.StatusBadRequest},
		{"cidr rejected", `{"ip":"10.0.0.0/8","duration":"1h"}`, http.StatusBadRequest},
		{"empty ip", `{"ip":"","duration":"1h"}`, http.StatusBadRequest},
		{"garbage duration", `{"ip":"9.9.9.12","duration":"forever"}`, http.StatusBadRequest},
		{"negative duration", `{"ip":"9.9.9.12","duration":"-1h"}`, http.StatusBadRequest},
		{"zero duration", `{"ip":"9.9.9.12","duration":"0s"}`, http.StatusBadRequest},
		{"oversize duration", `{"ip":"9.9.9.12","duration":"8760h"}`, http.StatusBadRequest},
		{"bad json", `{oops`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := serveAPI(testAPI(), http.MethodPost, "/api/block", tc.body)
			if w.Code != tc.want {
				t.Errorf("got %d, want %d (body %q)", w.Code, tc.want, w.Body.String())
			}
		})
	}
}

func TestHandleBlockPostThenUnblock(t *testing.T) {
	api := testAPI()
	if w := serveAPI(api, http.MethodPost, "/api/block", `{"ip":"8.8.8.8","duration":"1h"}`); w.Code != http.StatusCreated {
		t.Fatalf("block got %d", w.Code)
	}
	if !api.Store.IsBlocked("8.8.8.8") {
		t.Fatal("IP should be blocked after POST")
	}
	// Unblock also clears the kernel dedupe set without error even when
	// no iptables rule exists (best-effort path).
	if w := serveAPI(api, http.MethodDelete, "/api/block?ip=8.8.8.8", ""); w.Code != http.StatusNoContent {
		t.Fatalf("unblock got %d", w.Code)
	}
	if api.Store.IsBlocked("8.8.8.8") {
		t.Fatal("IP should be unblocked after DELETE")
	}
}

func TestHandleBlockDeleteValidation(t *testing.T) {
	cases := []struct {
		name   string
		target string
		want   int
	}{
		{"missing ip", "/api/block", http.StatusBadRequest},
		{"garbage ip", "/api/block?ip=nope", http.StatusBadRequest},
		{"cidr rejected", "/api/block?ip=10.0.0.0/8", http.StatusBadRequest},
		{"unknown single ip (no-op success)", "/api/block?ip=7.7.7.7", http.StatusNoContent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if w := serveAPI(testAPI(), http.MethodDelete, tc.target, ""); w.Code != tc.want {
				t.Errorf("got %d, want %d", w.Code, tc.want)
			}
		})
	}
}

func TestHandleConfigWhitelist(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int
	}{
		{"valid toggle", `{"waf":false}`, http.StatusAccepted},
		{"unknown key rejected", `{"rate_limit":999}`, http.StatusBadRequest},
		{"non-bool rejected", `{"waf":"off"}`, http.StatusBadRequest},
		{"empty object rejected", `{}`, http.StatusBadRequest},
		{"bad json", `{`, http.StatusBadRequest},
		{"wrong method", ``, http.StatusMethodNotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			method := http.MethodPatch
			target := "/api/config"
			if tc.name == "wrong method" {
				method = http.MethodGet
			}
			if w := serveAPI(testAPI(), method, target, tc.body); w.Code != tc.want {
				t.Errorf("got %d, want %d", w.Code, tc.want)
			}
		})
	}
}

func TestParseBlockIP(t *testing.T) {
	if got, ok := parseBlockIP("1.2.3.4"); !ok || got != "1.2.3.4" {
		t.Errorf("v4: got %q,%v", got, ok)
	}
	if got, ok := parseBlockIP("::1"); !ok || got != "::1" {
		t.Errorf("v6 loopback: got %q,%v", got, ok)
	}
	for _, bad := range []string{"", "nope", "10.0.0.0/8", "1.2.3.4/32", "999.1.1.1"} {
		if got, ok := parseBlockIP(bad); ok {
			t.Errorf("%q should be rejected, got %q", bad, got)
		}
	}
}
