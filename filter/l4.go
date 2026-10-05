package filter

import (
	"net"
	"time"

	"aegisedge/logger"
	"aegisedge/store"
)

type L4Filter struct {
	MaxConnPerIP int
	IdleTimeout  time.Duration
	Whitelist    map[string]bool
	store        store.Storer
}

func NewL4Filter(maxConn int, idleTimeout time.Duration, s store.Storer, whitelist []string) *L4Filter {
	wl := make(map[string]bool)
	for _, ip := range whitelist {
		wl[ip] = true
	}
	return &L4Filter{
		MaxConnPerIP: maxConn,
		IdleTimeout:  idleTimeout,
		Whitelist:    wl,
		store:        s,
	}
}

// AllowConnection attempts to admit a new connection from addr.
//
// Hardened 2026-09-25 per Finding 2.1: replaced the previous
// check-then-act pattern (GetCounter -> Increment) with a single
// atomic IncrementIfBelow call. The race window that previously
// allowed concurrent connections to overshoot MaxConnPerIP is gone.
//
// Returns (true, releaseFn) when the connection is admitted, or
// (false, noopFn) when it is refused. The releaseFn must be deferred
// by the caller (typically via defer) to ensure the counter is
// decremented when the connection closes.
func (f *L4Filter) AllowConnection(addr string) (bool, func()) {
	noop := func() {}
	// Performance Bypass: If limit is 0, skip all tracking and locks.
	if f.MaxConnPerIP <= 0 {
		return true, noop
	}

	host, _, _ := net.SplitHostPort(addr)
	if host == "" {
		// Defensive: addr was already an IP.
		host = addr
	}

	// Whitelist takes absolute precedence.
	if f.Whitelist[host] {
		return true, noop
	}

	key := "l4:conn:" + host
	n, err := f.store.IncrementIfBelow(key, int64(f.MaxConnPerIP), f.IdleTimeout)
	if err != nil {
		logger.Error("L4 store error (fail closed)", "err", err, "ip", host)
		return false, noop // fail closed
	}
	if n > int64(f.MaxConnPerIP) {
		logger.Warn("L4 connection limit exceeded", "ip", host, "limit", f.MaxConnPerIP)
		return false, noop
	}

	release := func() {
		if _, err := f.store.Decrement(key); err != nil {
			logger.Error("L4 release failed", "ip", host, "err", err)
		}
	}
	return true, release
}

// ReleaseConnection decrements the per-IP connection counter for addr.
// Kept as a thin wrapper for backward compatibility with any caller
// that still passes a raw net.Conn-style address; new code should
// defer the release function returned by AllowConnection instead.
func (f *L4Filter) ReleaseConnection(addr string) {
	if f.MaxConnPerIP <= 0 {
		return
	}
	host, _, _ := net.SplitHostPort(addr)
	if host == "" {
		host = addr
	}
	key := "l4:conn:" + host
	if _, err := f.store.Decrement(key); err != nil {
		logger.Error("L4 decrement failed", "ip", host, "err", err)
	}
}
