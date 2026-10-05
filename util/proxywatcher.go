package util

import (
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ProxyWatcher maintains a live, hot-swappable list of trusted proxy CIDRs.
// It re-discovers from CSF, cPHulk, and iptables on a configurable interval
// and supports on-demand reloads via Reload().
type ProxyWatcher struct {
	nets      atomic.Value // stores []*net.IPNet — for CIDR matching
	cache     atomic.Value // stores map[string]bool — fast-path for exact IP matches
	manual    []string     // static entries from env / API calls
	mu        sync.Mutex   // guards manual slice and Reload()
	stop      chan struct{}
	onReload  func()       // optional callback fired after every reload
}

// NewProxyWatcher creates a watcher, does an immediate load, then refreshes
// on the given interval. Pass interval=0 to disable background refresh.
func NewProxyWatcher(manualList string, interval time.Duration) *ProxyWatcher {
	w := &ProxyWatcher{
		stop: make(chan struct{}),
	}
	// Initialize with empty maps to avoid nil checks on hot path
	w.cache.Store(make(map[string]bool))
	w.nets.Store([]*net.IPNet{})

	// Parse static manual entries once.
	for _, e := range strings.Split(manualList, ",") {
		e = strings.TrimSpace(e)
		if e != "" {
			w.manual = append(w.manual, e)
		}
	}
	w.reload()

	if interval > 0 {
		go w.loop(interval)
	}
	return w
}

// IsTrusted returns true if ip is within any currently trusted network.
// Uses atomic load — zero contention on the hot path.
func (w *ProxyWatcher) IsTrusted(ipStr string) bool {
	// Fast-Path: Check string cache first (Zero allocation, O(1))
	cache, _ := w.cache.Load().(map[string]bool)
	if cache[ipStr] {
		return true
	}

	// Slow-Path: Parse and CIDR match
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	nets, _ := w.nets.Load().([]*net.IPNet)
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Reload forces an immediate re-read of all sources. Safe to call concurrently.
// The onReload hook runs WITHOUT holding mu, so a hook that calls back into
// the watcher (or a panicking hook) cannot deadlock or double-unlock.
func (w *ProxyWatcher) Reload() {
	w.mu.Lock()
	w.reload()
	hook := w.onReload
	w.mu.Unlock()
	if hook != nil {
		hook()
	}
}

// SetOnReloadHook registers a function to be called (outside the
// watcher mutex) after every Reload. Used by the middleware package
// to invalidate the IP-resolution cache when the trusted-proxy set
// changes (Finding 4.2). Hardened 2026-09-25.
func (w *ProxyWatcher) SetOnReloadHook(fn func()) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.onReload = fn
}

// AddManual adds a single IP or CIDR to the permanent manual list and reloads.
func (w *ProxyWatcher) AddManual(entry string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.manual = append(w.manual, entry)
	w.reload()
}

// RemoveManual removes an entry from the manual list and reloads.
func (w *ProxyWatcher) RemoveManual(entry string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	updated := w.manual[:0]
	for _, e := range w.manual {
		if e != entry {
			updated = append(updated, e)
		}
	}
	w.manual = updated
	w.reload()
}

// Stop cancels the background refresh goroutine.
func (w *ProxyWatcher) Stop() {
	close(w.stop)
}

// reload (must be called with mu held, or single-threaded at init) rebuilds
// the live net list from all sources and atomically swaps it in.
func (w *ProxyWatcher) reload() {
	entries := make([]string, 0, len(w.manual))
	entries = append(entries, w.manual...)
	entries = append(entries, DiscoverTrustedProxies()...)

	nets := parseTrustedList(entries)
	w.nets.Store(nets)

	// Rebuild string cache for exact IPs
	cache := make(map[string]bool)
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// If it's a single IP (no mask), add to cache
		if !strings.Contains(entry, "/") {
			cache[entry] = true
		} else {
			// If it's a /32 or /128 CIDR, add the IP part to cache too
			if strings.HasSuffix(entry, "/32") || strings.HasSuffix(entry, "/128") {
				parts := strings.Split(entry, "/")
				cache[parts[0]] = true
			}
		}
	}
	w.cache.Store(cache)
}

func (w *ProxyWatcher) loop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			w.Reload()
		case <-w.stop:
			return
		}
	}
}

// parseTrustedList converts string entries to []*net.IPNet.
func parseTrustedList(entries []string) []*net.IPNet {
	seen := make(map[string]struct{})
	var nets []*net.IPNet
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, seen := seen[entry]; seen {
			continue
		}
		seen[entry] = struct{}{}

		if !strings.Contains(entry, "/") {
			if strings.Contains(entry, ":") {
				entry += "/128"
			} else {
				entry += "/32"
			}
		}
		_, cidr, err := net.ParseCIDR(entry)
		if err == nil {
			nets = append(nets, cidr)
		}
	}
	return nets
}
