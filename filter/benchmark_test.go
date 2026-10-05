package filter

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"aegisedge/store"
	"aegisedge/logger"
)

func init() {
	log.SetOutput(io.Discard)
	logger.SetLevel("ERROR")
}

func newTestHandler(rateLimit float64, burst int, penalize bool) (http.Handler, *store.LocalStore) {
	s := store.NewLocalStore()
	f := NewL7Filter(rateLimit, burst, nil)
	rep := NewReputationManager(s)
	if penalize {
		rep.Penalize("192.0.2.1")
	}
	handler := f.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), rep)
	return handler, s
}

func newReq(remoteAddr string) *http.Request {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = remoteAddr
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	return req
}

// BenchmarkL7Filter measures single-request latency (ns/op) for the L7 middleware stack.
func BenchmarkL7Filter(b *testing.B) {
	handler, _ := newTestHandler(100000.0, 1000000, false)
	req := newReq("192.0.2.1:1234")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
	}
}

// BenchmarkL7FilterParallel measures parallel throughput (ns/op) for the L7 middleware stack.
func BenchmarkL7FilterParallel(b *testing.B) {
	handler, _ := newTestHandler(100000.0, 1000000, false)
	req := newReq("192.0.2.1:1234")
	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
		}
	})
}

// BenchmarkL7FilterRateLimited measures req/sec with strict rate limiting (1 RPS).
func BenchmarkL7FilterRateLimited(b *testing.B) {
	handler, _ := newTestHandler(1000.0, 1000, false)
	req := newReq("10.0.0.1:1234")
	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
		}
	})
}

// BenchmarkL7FilterWithReputation measures single-request latency with penalized reputation.
func BenchmarkL7FilterWithReputation(b *testing.B) {
	handler, _ := newTestHandler(100000.0, 1000000, true)
	req := newReq("192.0.2.1:1234")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
	}
}

// BenchmarkFullFilterPipeline measures parallel throughput through all L7 filters.
func BenchmarkFullFilterPipeline(b *testing.B) {
	handler, _ := newTestHandler(100000.0, 1000000, false)
	req := newReq("192.0.2.1:1234")
	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
		}
	})
}

// BenchmarkL7FilterWithWAF measures single-request latency with WAF enabled.
func BenchmarkL7FilterWithWAF(b *testing.B) {
	handler, _ := newTestHandler(100000.0, 1000000, false)
	wafHandler := WAFMiddleware(handler)
	req := newReq("192.0.2.1:1234")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		wafHandler.ServeHTTP(rr, req)
	}
}

// BenchmarkFullPipelineWithWAF measures parallel throughput with WAF and all filters.
func BenchmarkFullPipelineWithWAF(b *testing.B) {
	handler, _ := newTestHandler(100000.0, 1000000, false)
	wafHandler := WAFMiddleware(handler)
	req := newReq("192.0.2.1:1234")
	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rr := httptest.NewRecorder()
			wafHandler.ServeHTTP(rr, req)
		}
	})
}

// BenchmarkL7FilterDuration measures real throughput in req/sec over a fixed time window.
func BenchmarkL7FilterDuration(b *testing.B) {
	handler, _ := newTestHandler(100000.0, 1000000, false)
	req := newReq("192.0.2.1:1234")
	b.ResetTimer()
	b.ReportAllocs()
	b.StopTimer()
	time.Sleep(100 * time.Millisecond) // warmup
	b.StartTimer()
	deadline := time.Now().Add(time.Second)
	var count uint64
	for time.Now().Before(deadline) {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		count++
	}
	b.Logf("Duration: 1s, req/sec: %d", count)
}
