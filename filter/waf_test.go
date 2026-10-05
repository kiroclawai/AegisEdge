package filter

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWAFMiddleware(t *testing.T) {
	handler := WAFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name       string
		method     string
		url        string
		body       string
		wantStatus int
	}{
		{"Clean GET", "GET", "/", "", http.StatusOK},
		{"XSS in Query", "GET", "/?q=<script>alert(1)</script>", "", http.StatusBadRequest},
		{"CMDi in Query", "GET", "/?exec=;cat%20/etc/passwd", "", http.StatusBadRequest},
		{"Traversal in Path", "GET", "/../../etc/passwd", "", http.StatusBadRequest},
		{"Clean POST", "POST", "/", "foo=bar", http.StatusOK},
		{"SQLi in Body", "POST", "/", "id=1' OR '1'='1", http.StatusBadRequest},
		{"XSS in Body", "POST", "/", "<script>alert(1)</script>", http.StatusBadRequest},
		{"CMDi in Body", "POST", "/", "ping -c 1 8.8.8.8; cat /etc/passwd", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var bodyReader io.Reader
			if tt.body != "" {
				bodyReader = strings.NewReader(tt.body)
			}
			req := httptest.NewRequest(tt.method, tt.url, bodyReader)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("%s: got status %d, want %d", tt.name, rr.Code, tt.wantStatus)
			}
		})
	}
}
