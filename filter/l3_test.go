package filter

import (
	"testing"
)

func TestL3Filter(t *testing.T) {
	f := NewL3Filter([]string{"1.2.3.4"}, []string{"127.0.0.1"})

	// 1.2.3.4 was in the initial blacklist
	if !f.IsBlacklisted("1.2.3.4") {
		t.Error("Expected 1.2.3.4 to be blacklisted from constructor")
	}
	if f.IsBlacklisted("8.8.8.8") {
		t.Error("Expected 8.8.8.8 to not be blacklisted initially")
	}

	// Whitelist takes precedence
	if !f.IsWhitelisted("127.0.0.1") {
		t.Error("Expected 127.0.0.1 to be whitelisted")
	}
	if f.IsBlacklisted("127.0.0.1") {
		t.Error("Expected 127.0.0.1 to NOT be blacklisted (whitelist precedence)")
	}

	// AddIP promotes via AddIP
	f.AddIP("8.8.8.8")
	if !f.IsBlacklisted("8.8.8.8") {
		t.Error("Expected 8.8.8.8 to be blacklisted after AddIP")
	}
}
