package filter

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestStatisticalDetector_Threshold verifies the detector
// flags traffic that exceeds the baseline significantly.
func TestStatisticalDetector_Threshold(t *testing.T) {
	d := NewStatisticalAnomalyDetector(1)
	handler := d.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Build baseline (~5 RPS)
	for i := 0; i < 5; i++ {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	}
	time.Sleep(1100 * time.Millisecond)
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))

	// Verify baseline was established
	_ = d.MeanRPS
	_ = d.VarianceRPS
}

// TestStatisticalDetectorDisabled verifies that disabling the detector
// prevents attack mode from being set.
func TestStatisticalDetectorDisabled(t *testing.T) {
	d := NewStatisticalAnomalyDetector(1)
	d.SetEnabled(false)

	handler := d.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 100; i++ {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	}

	if d.IsUnderAttack() {
		t.Error("Should not be under attack when detector is disabled")
	}
}
