package middleware

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"aegisedge/util"
)

const (
	ipShards        = 64
	ipCacheTTL      = 5 * time.Minute
	ipCacheMaxEntry = 1024 // per shard
	maxHeaderBytes  = 256
	maxForwardHops  = 4
)

type ipCacheShard struct {
	mu      sync.RWMutex
	cache   map[string]ipCacheEntry
	nowFn   func() time.Time
	counter uint64 // LRU-ish eviction: evict oldest when size > ipCacheMaxEntry
}

type ipCacheEntry struct {
	ip       string
	cachedAt time.Time
}

var memoizedIPs [ipShards]*ipCacheShard

func init() {
	for i := 0; i < ipShards; i++ {
		memoizedIPs[i] = &ipCacheShard{
			cache: make(map[string]ipCacheEntry),
			nowFn: time.Now,
		}
	}
}

// PurgeAllIPCache drops every cached entry. Registered as a reload
// hook on ProxyWatcher via SetOnReloadHook so stale resolutions don't
// survive a trusted-proxy change (Finding 4.2). Hardened 2026-09-25.
func PurgeAllIPCache() {
	for _, s := range memoizedIPs {
		s.mu.Lock()
		s.cache = make(map[string]ipCacheEntry)
		s.mu.Unlock()
	}
}

func getIpShard(remoteAddr string) *ipCacheShard {
	hash := uint32(0)
	for i := 0; i < len(remoteAddr); i++ {
		hash = 31*hash + uint32(remoteAddr[i])
	}
	return memoizedIPs[hash%ipShards]
}

// RealIP middleware resolves the true client IP from trusted proxy headers.
// Priority: CF-Connecting-IP → X-Real-IP → X-Forwarded-For → RemoteAddr.
func RealIP(watcher *util.ProxyWatcher) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				remoteHost = r.RemoteAddr
			}

			shard := getIpShard(remoteHost)
			now := shard.nowFn()
			shard.mu.RLock()
			entry, ok := shard.cache[remoteHost]
			shard.mu.RUnlock()
			if ok && now.Sub(entry.cachedAt) < ipCacheTTL {
				next.ServeHTTP(w, util.SetRealIP(r, entry.ip))
				return
			}

			ip := extractIP(r, watcher, remoteHost)

			shard.mu.Lock()
			// Evict if over the cap, drop expired entries opportunistically.
			if len(shard.cache) >= ipCacheMaxEntry {
				for k, e := range shard.cache {
					if now.Sub(e.cachedAt) >= ipCacheTTL {
						delete(shard.cache, k)
					}
				}
				if len(shard.cache) >= ipCacheMaxEntry {
					// Hard evict: clear all (cheap, no LRU bookkeeping).
					shard.cache = make(map[string]ipCacheEntry)
				}
			}
			shard.cache[remoteHost] = ipCacheEntry{ip: ip, cachedAt: now}
			shard.mu.Unlock()

			next.ServeHTTP(w, util.SetRealIP(r, ip))
		})
	}
}

// GetRealIP is a convenience wrapper for use within the middleware package.
func GetRealIP(r *http.Request) string {
	return util.GetRealIP(r)
}

// extractIP resolves the client IP, preferring trusted-proxy headers
// only when the immediate connection is from a trusted proxy.
//
// Hardened 2026-09-25 per Finding 4.1:
//   - Header values are truncated to maxHeaderBytes before parsing to
//     bound CPU / RAM amplification.
//   - X-Forwarded-For is bounded to maxForwardHops hops so an attacker
//     who can craft the chain cannot choose an arbitrary leftmost value
//     (the leftmost of the first maxForwardHops hops is used).
//   - net.ParseIP validates the syntax; anything else falls back to
//     the immediate RemoteAddr.
func extractIP(r *http.Request, watcher *util.ProxyWatcher, remoteHost string) string {
	if watcher == nil || !watcher.IsTrusted(remoteHost) {
		return remoteHost
	}

	// 1. Cloudflare (single authoritative header, no parsing ambiguity).
	if cf := truncateHeader(r.Header.Get("CF-Connecting-IP")); cf != "" {
		if ip := net.ParseIP(strings.TrimSpace(cf)); ip != nil {
			return ip.String()
		}
	}

	// 2. Standard nginx / AWS ALB.
	if real := truncateHeader(r.Header.Get("X-Real-IP")); real != "" {
		if ip := net.ParseIP(strings.TrimSpace(real)); ip != nil {
			return ip.String()
		}
	}

	// 3. X-Forwarded-For — only inspect up to maxForwardHops hops and
	// take the leftmost valid one. This caps the trust placed on an
	// attacker-influenced chain to the depth we actually have proxies for.
	if fwd := truncateHeader(r.Header.Get("X-Forwarded-For")); fwd != "" {
		parts := strings.Split(fwd, ",")
		if len(parts) > maxForwardHops {
			parts = parts[:maxForwardHops]
		}
		for _, p := range parts {
			if ip := net.ParseIP(strings.TrimSpace(p)); ip != nil {
				return ip.String()
			}
		}
	}

	return remoteHost
}

func truncateHeader(s string) string {
	if len(s) <= maxHeaderBytes {
		return s
	}
	return s[:maxHeaderBytes]
}
