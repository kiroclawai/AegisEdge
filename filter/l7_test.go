package filter

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"aegisedge/store"
)

func TestL7Filter_SmokeTest(t *testing.T) {
	s := store.NewLocalStore()
	f := NewL7Filter(1000.0, 10000, nil)
	rep := NewReputationManager(s)
	handler := f.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), rep)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("First request should pass, got %d", rr.Code)
	}
	rep.Penalize("192.0.2.1")
	mult := rep.GetMultiplier("192.0.2.1")
	if mult >= 1.0 {
		t.Errorf("Expected multiplier < 1.0 after penalty, got %f", mult)
	}
	f.Stop()
}

func TestL7FilterRateLimit(t *testing.T) {
	s := store.NewLocalStore()
	f := NewL7Filter(1.0, 1, nil)
	rep := NewReputationManager(s)
	handler := f.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), rep)

	req1 := httptest.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "10.0.0.1:1234"
	req1.Header.Set("User-Agent", "Mozilla/5.0")
	req1.Header.Set("Accept", "text/html")
	req1.Header.Set("Accept-Encoding", "gzip")
	req1.Header.Set("Connection", "keep-alive")
	req1.Header.Set("Sec-Fetch-Dest", "document")
	req1.Header.Set("Sec-Fetch-Mode", "navigate")
	req1.Header.Set("Sec-Fetch-Site", "none")
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Errorf("First request should pass, got %d", rr1.Code)
	}

	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "10.0.0.1:1234"
	req2.Header.Set("User-Agent", "Mozilla/5.0")
	req2.Header.Set("Accept", "text/html")
	req2.Header.Set("Accept-Encoding", "gzip")
	req2.Header.Set("Connection", "keep-alive")
	req2.Header.Set("Sec-Fetch-Dest", "document")
	req2.Header.Set("Sec-Fetch-Mode", "navigate")
	req2.Header.Set("Sec-Fetch-Site", "none")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Errorf("Second request should be rate limited, got %d", rr2.Code)
	}
	f.Stop()
}

func TestL7FilterNoUserAgent(t *testing.T) {
	s := store.NewLocalStore()
	f := NewL7Filter(1000.0, 10000, nil)
	rep := NewReputationManager(s)
	handler := f.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), rep)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("Request without User-Agent should be forbidden, got %d", rr.Code)
	}
	f.Stop()
}

func TestL7FilterStop(t *testing.T) {
	f := NewL7Filter(5.0, 10, nil)
	if f.stop == nil {
		t.Error("stop channel should be initialized")
	}
	f.Stop()
}

func TestL7FilterCleanup(t *testing.T) {
	f := NewL7Filter(100.0, 1000, nil)
	time.Sleep(100 * time.Millisecond)
	f.Stop()
}

func TestL7FilterReputation(t *testing.T) {
	s := store.NewLocalStore()
	f := NewL7Filter(100.0, 100, nil)
	rep := NewReputationManager(s)
	handler := f.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), rep)
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))

	rep.Penalize("10.0.0.1")
	rep.Penalize("10.0.0.1")
	rep.Penalize("10.0.0.1")
	mult := rep.GetMultiplier("10.0.0.1")
	if mult >= 1.0 {
		t.Errorf("Expected multiplier < 1.0 for penalized IP, got %f", mult)
	}
	f.Stop()
}

func TestL7FilterPlainBot(t *testing.T) {
	s := store.NewLocalStore()
	f := NewL7Filter(100.0, 100, nil)
	rep := NewReputationManager(s)
	handler := f.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), rep)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	req.Header.Set("User-Agent", "")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("Plain bot request should be forbidden, got %d", rr.Code)
	}
	f.Stop()
}

func TestL7FilterHealthVerify(t *testing.T) {
	s := store.NewLocalStore()
	f := NewL7Filter(1000.0, 10000, nil)
	rep := NewReputationManager(s)
	handler := f.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), rep)

	req := httptest.NewRequest("GET", "/health", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("Health check should pass, got %d", rr.Code)
	}
	f.Stop()
}
