package filter

import (
	"testing"
	"time"

	"aegisedge/store"
)

func TestL4Filter(t *testing.T) {
	s := store.NewLocalStore()
	// Set a small limit of 2 conns per IP
	f := NewL4Filter(2, 1*time.Minute, s, []string{"127.0.0.1"})

	addr := "1.1.1.1:1234"
	ip := "1.1.1.1"

	allowed, release1 := f.AllowConnection(addr)
	if !allowed {
		t.Error("Initial connection should be allowed")
	}

	count, err := s.GetCounter("l4:conn:" + ip)
	if err != nil {
		t.Fatalf("GetCounter failed: %v", err)
	}
	if count != 1 {
		t.Errorf("Expected 1 connection in store for %s, got %d", ip, count)
	}

	allowed, release2 := f.AllowConnection(addr)
	if !allowed {
		t.Error("Second connection should be allowed")
	}

	// Third connection should be blocked (limit is 2)
	if allowed3, _ := f.AllowConnection(addr); allowed3 {
		t.Error("Third connection should be blocked (limit is 2)")
	}

	// Whitelist bypass
	if allowedWL, _ := f.AllowConnection("127.0.0.1:9999"); !allowedWL {
		t.Error("Whitelisted IP should always be allowed")
	}

	release1()
	count, err = s.GetCounter("l4:conn:" + ip)
	if err != nil {
		t.Fatalf("GetCounter failed: %v", err)
	}
	// After releasing one of two held connections, count decrements to 1
	if count != 1 {
		t.Errorf("Expected 1 connection after one release, got %d", count)
	}

	// Release again
	release2()
	count, err = s.GetCounter("l4:conn:" + ip)
	if err != nil {
		t.Fatalf("GetCounter failed: %v", err)
	}
	if count != 0 {
		t.Errorf("Expected 0 connections after second release, got %d", count)
	}

	// Zero limit = bypass
	f2 := NewL4Filter(0, 1*time.Minute, s, nil)
	if allowedZ, _ := f2.AllowConnection("10.0.0.1:1234"); !allowedZ {
		t.Error("Zero limit should allow all connections")
	}
}
