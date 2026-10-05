package manager

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	//"sync"
	"strings"
	"sync/atomic"
	"time"

	"aegisedge/logger"
	"aegisedge/store"
	"aegisedge/filter"
	utilpkg "aegisedge/util"
)

// LiveToggles holds the runtime feature flag state, lockless for extreme throughput.
type LiveToggles struct {
	WAF       atomic.Bool
	GeoIP     atomic.Bool
	Challenge atomic.Bool
	Anomaly   atomic.Bool
	Stats     atomic.Bool
}

func NewLiveToggles(waf, geoip, challenge, anomaly, stats bool) *LiveToggles {
	t := &LiveToggles{}
	t.WAF.Store(waf)
	t.GeoIP.Store(geoip)
	t.Challenge.Store(challenge)
	t.Anomaly.Store(anomaly)
	t.Stats.Store(stats)
	return t
}

func (t *LiveToggles) IsEnabled(feature string) bool {
	switch feature {
	case "waf":
		return t.WAF.Load()
	case "geoip":
		return t.GeoIP.Load()
	case "challenge":
		return t.Challenge.Load()
	case "anomaly":
		return t.Anomaly.Load()
	case "stats":
		return t.Stats.Load()
	}
	return true
}

func (t *LiveToggles) Set(feature string, enabled bool) {
	switch feature {
	case "waf":
		t.WAF.Store(enabled)
	case "geoip":
		t.GeoIP.Store(enabled)
	case "challenge":
		t.Challenge.Store(enabled)
	case "anomaly":
		t.Anomaly.Store(enabled)
	case "stats":
		t.Stats.Store(enabled)
		filter.SetMetricsEnabled(enabled)
	}
}

func (t *LiveToggles) Snapshot() map[string]bool {
	return map[string]bool{
		"waf":       t.WAF.Load(),
		"geoip":     t.GeoIP.Load(),
		"challenge": t.Challenge.Load(),
		"anomaly":   t.Anomaly.Load(),
		"stats":     t.Stats.Load(),
	}
}

// ManagementAPI provides runtime control over AegisEdge state.
type ManagementAPI struct {
	Store        store.Storer
	Toggles      *LiveToggles
	ProxyWatcher *utilpkg.ProxyWatcher
	RequestCount atomic.Uint64
	StartTime    time.Time
	// Version is the release version stamped by main (main.Version).
	// Empty when constructed directly (e.g. in tests) — omitted from
	// /api/status in that case.
	Version string
}

type BlockRequest struct {
	IP       string `json:"ip"`
	Duration string `json:"duration"` // e.g. "1h", "30m", "permanent"
}

func NewManagementAPI(s store.Storer, toggles *LiveToggles, pw *utilpkg.ProxyWatcher) *ManagementAPI {
	return &ManagementAPI{
		Store:        s,
		Toggles:      toggles,
		ProxyWatcher: pw,
		StartTime:    time.Now(),
	}
}

func (api *ManagementAPI) TrackRequest() {
	api.RequestCount.Add(1)
}

func (api *ManagementAPI) ServeHTTP(mux *http.ServeMux) {
	mux.HandleFunc("/api/status", api.handleStatus)
	mux.HandleFunc("/api/block", api.handleBlock)
	mux.HandleFunc("/api/config", api.handleConfig)
	// Trusted proxy management — live, no restart required
	mux.HandleFunc("/api/proxy/reload", api.handleProxyReload)
	mux.HandleFunc("/api/proxy/add", api.handleProxyAdd)
	mux.HandleFunc("/api/proxy/remove", api.handleProxyRemove)
}

// allowedConfigKeys is the exhaustive whitelist of feature toggles that
// PATCH /api/config may mutate. Any other key is rejected.
// Hardened 2026-09-25 per Finding 1.4: previous code accepted arbitrary
// JSON keys and merged into live config, letting an attacker disable
// WAF, whitelist the world, or raise rate limits unbounded.
var allowedConfigKeys = map[string]struct{}{
	"waf":       {},
	"geoip":     {},
	"challenge": {},
	"anomaly":   {},
	"stats":     {},
}

func (api *ManagementAPI) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		http.Error(w, "Use PATCH", http.StatusMethodNotAllowed)
		return
	}

	// Cap body to 4 KB — a real toggle payload is ~5 fields.
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var updates map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		http.Error(w, "Invalid body", http.StatusBadRequest)
		return
	}

	// Snapshot the pre-patch state for the audit log (Finding 1.4).
	before := api.Toggles.Snapshot()
	applied := make(map[string]bool)

	for key, raw := range updates {
		if _, ok := allowedConfigKeys[key]; !ok {
			http.Error(w, "unknown key: "+key, http.StatusBadRequest)
			return
		}
		var enabled bool
		if err := json.Unmarshal(raw, &enabled); err != nil {
			http.Error(w, key+" must be boolean", http.StatusBadRequest)
			return
		}
		api.Toggles.Set(key, enabled)
		applied[key] = enabled
	}

	if len(applied) == 0 {
		http.Error(w, "no togglable keys provided", http.StatusBadRequest)
		return
	}

	// Log the diff so an audit reader sees what changed and from what.
	logger.Info("Feature toggles patched via API",
		"caller", r.RemoteAddr,
		"before", before,
		"applied", applied,
	)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Toggles applied (live, no restart needed)",
		"toggles": api.Toggles.Snapshot(),
	})
}

func (api *ManagementAPI) handleStatus(w http.ResponseWriter, r *http.Request) {
	blocks, err := api.Store.ListBlocks()
	if err != nil {
		http.Error(w, "Failed to list blocks", http.StatusInternalServerError)
		return
	}

	totalReqs := api.RequestCount.Load()
	uptimeSeconds := time.Since(api.StartTime).Seconds()
	avgRps := float64(totalReqs) / uptimeSeconds

	status := map[string]any{
		"status":           "active",
		"uptime_seconds":   int(uptimeSeconds),
		"total_requests":   totalReqs,
		"average_rps":      avgRps,
		"active_blocks":    blocks,
		"fast_path_blocks": filter.GetSoftBlocks(),
		"toggles":          api.Toggles.Snapshot(),
		"timestamp":        time.Now(),
	}
	if api.Version != "" {
		status["version"] = api.Version
	}
	json.NewEncoder(w).Encode(status)
}

func (api *ManagementAPI) handleBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 2048)
		var req BlockRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		req.IP = strings.TrimSpace(req.IP)
		// CIDR ranges are not supported for blocks — refuse rather
		// than storing a range key the data plane never matches.
		ip, ok := parseBlockIP(req.IP)
		if !ok {
			http.Error(w, "ip must be a single valid IP address (CIDR ranges not supported)", http.StatusBadRequest)
			return
		}

		dur := 24 * time.Hour // Default
		blockType := "temp"
		if req.Duration == "" {
			// keep default 24h
		} else if req.Duration == "permanent" {
			dur = 10 * 365 * 24 * time.Hour
			blockType = "hard"
		} else if d, err := time.ParseDuration(req.Duration); err == nil {
			if d <= 0 || d > 30*24*time.Hour {
				http.Error(w, "duration must be between 1s and 720h (30d), or \"permanent\"", http.StatusBadRequest)
				return
			}
			dur = d
		} else {
			http.Error(w, "duration must be a Go duration (e.g. 30m, 1h) or \"permanent\"", http.StatusBadRequest)
			return
		}

		api.Store.Block(ip, dur, blockType)
		logger.Info("Manual IP block applied", "ip", ip, "duration", dur, "type", blockType)
		w.WriteHeader(http.StatusCreated)
		return
	}

	if r.Method == http.MethodDelete {
		raw := strings.TrimSpace(r.URL.Query().Get("ip"))
		if raw == "" {
			http.Error(w, "IP required", http.StatusBadRequest)
			return
		}
		ip, ok := parseBlockIP(raw)
		if !ok {
			http.Error(w, "ip must be a single valid IP address (CIDR ranges not supported)", http.StatusBadRequest)
			return
		}
		if err := api.Store.Unblock(ip); err != nil {
			http.Error(w, "Clear failed", http.StatusInternalServerError)
			return
		}
		filter.ClearKernelBlock(ip)
		// Best-effort: a reputation-terminal IP also holds an iptables
		// DROP rule. Without this the manual unblock clears only the
		// app layer and the kernel keeps dropping packets indefinitely.
		// Hardened 2026-10-05: failure here must not fail the request
		// (app state is already cleared) — it is logged for the operator.
		if err := filter.UnblockIPKernel(ip); err != nil {
			logger.Warn("Manual unblock: kernel rule removal failed (app block cleared)", "ip", ip, "err", err)
		}
		logger.Info("Manual block clearance", "ip", ip)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// parseBlockIP normalizes a block-target string to a single IP address.
// Returns ("", false) for empty input, garbage, and CIDR ranges — the
// data plane keys blocks by exact IP, so anything else would store a
// key that never matches (POST) or address a bogus firewall rule (DELETE).
func parseBlockIP(s string) (string, bool) {
	if s == "" {
		return "", false
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.String(), true
	}
	return "", false
}

// handleProxyReload forces an immediate re-read of CSF/cPHulk/iptables.
// POST /api/proxy/reload
func (api *ManagementAPI) handleProxyReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Use POST", http.StatusMethodNotAllowed)
		return
	}
	if api.ProxyWatcher == nil {
		http.Error(w, "ProxyWatcher not initialised", http.StatusServiceUnavailable)
		return
	}
	api.ProxyWatcher.Reload()
	logger.Info("Trusted proxy list reloaded via API")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "reloaded"})
}

// handleProxyAdd adds a permanent manual IP/CIDR to the trusted list.
// POST /api/proxy/add   body: {"entry": "1.2.3.4"} or {"entry": "10.0.0.0/8"}
//
// Hardened 2026-09-25 per Finding 1.3:
//   - Body capped at 1 KB (no need for more).
//   - Entry must parse as an IP or CIDR.
//   - /0 is always rejected (no "trust the whole internet").
//   - Entries overlapping RFC1918, loopback, link-local, multicast,
//     or cloud-metadata CIDRs are rejected to prevent IP-spoofing via
//     the trusted-proxy chain.
//   - Caller IP and remote addr are logged for audit.
func (api *ManagementAPI) handleProxyAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Use POST", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	var body struct {
		Entry string `json:"entry"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Entry == "" {
		http.Error(w, "body must be {\"entry\": \"<ip-or-cidr>\"}", http.StatusBadRequest)
		return
	}
	if err := validateTrustedEntry(body.Entry); err != nil {
		http.Error(w, "rejected: "+err.Error(), http.StatusBadRequest)
		return
	}
	api.ProxyWatcher.AddManual(body.Entry)
	logger.Info("Trusted proxy entry added via API",
		"entry", body.Entry,
		"caller", r.RemoteAddr,
	)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "added", "entry": body.Entry})
}

// handleProxyRemove removes a manual IP/CIDR from the trusted list.
// DELETE /api/proxy/remove?entry=1.2.3.4
func (api *ManagementAPI) handleProxyRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Use DELETE", http.StatusMethodNotAllowed)
		return
	}
	entry := r.URL.Query().Get("entry")
	if entry == "" {
		http.Error(w, "?entry= required", http.StatusBadRequest)
		return
	}
	if err := validateTrustedEntry(entry); err != nil {
		http.Error(w, "rejected: "+err.Error(), http.StatusBadRequest)
		return
	}
	api.ProxyWatcher.RemoveManual(entry)
	logger.Info("Trusted proxy entry removed via API",
		"entry", entry,
		"caller", r.RemoteAddr,
	)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "removed", "entry": entry})
}

// validateTrustedEntry returns nil if the entry is an acceptable IP
// or CIDR for the trusted-proxy list, otherwise an error explaining
// the rejection reason. Used by handleProxyAdd/handleProxyRemove.
//
// Hardened 2026-09-25 per Finding 1.3: prevents adding /0 (global
// trust) and ranges that overlap reserved / metadata address space
// (which would let an attacker spoof their client IP via the trusted
// proxy chain).
func validateTrustedEntry(entry string) error {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return errors.New("empty entry")
	}
	// Normalise: bare IPs become /32 or /128.
	normalized := entry
	if !strings.Contains(normalized, "/") {
		if strings.Contains(normalized, ":") {
			normalized += "/128"
		} else {
			normalized += "/32"
		}
	}
	// Parse as CIDR.
	ip, ipNet, err := net.ParseCIDR(normalized)
	if err != nil {
		return fmt.Errorf("not a valid IP or CIDR: %q", entry)
	}
	// /0 is never acceptable — that trusts the entire address space.
	ones, bits := ipNet.Mask.Size()
	if ones == 0 {
		return errors.New("refusing to trust the entire address space (/0)")
	}
	_ = bits
	_ = ip
	// Reject ranges overlapping reserved / private / metadata space.
	for _, reserved := range reservedCIDRs {
		if ipNet.Contains(reserved.first) || reserved.net.Contains(ip) {
			return fmt.Errorf("range overlaps reserved space %s", reserved.label)
		}
	}
	// Reject loopback, multicast, unspecified, link-local explicitly.
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		return errors.New("range points at loopback, link-local, multicast, or unspecified space")
	}
	return nil
}

type reservedRange struct {
	label string
	net   *net.IPNet
	// first is an arbitrary IP inside the range; used only as a probe
	// for the IPNet.Contains check (the bidirectional overlap test).
	first net.IP
}

// reservedCIDRs enumerates the CIDR ranges that may never appear in the
// trusted-proxy list. Hardened 2026-09-25 per Finding 1.3.
var reservedCIDRs = func() []reservedRange {
	cidrs := []string{
		"0.0.0.0/0",          // placeholder; the /0 test above catches it
		"10.0.0.0/8",         // RFC1918
		"172.16.0.0/12",      // RFC1918
		"192.168.0.0/16",     // RFC1918
		"127.0.0.0/8",        // loopback
		"169.254.0.0/16",     // link-local (incl. AWS / Azure / GCP metadata)
		"100.64.0.0/10",      // CGNAT / shared address space
		"224.0.0.0/4",        // multicast
		"240.0.0.0/4",        // reserved / future use
		"255.255.255.255/32", // broadcast
		"::1/128",            // IPv6 loopback
		"fc00::/7",           // IPv6 ULA
		"fe80::/10",          // IPv6 link-local
		"ff00::/8",           // IPv6 multicast
	}
	out := make([]reservedRange, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			continue // skip bad entries rather than panic
		}
		first := make(net.IP, len(n.IP))
		copy(first, n.IP)
		out = append(out, reservedRange{label: c, net: n, first: first})
	}
	return out
}()

// Ensure utilpkg is used (ProxyWatcher field references it).
var _ *utilpkg.ProxyWatcher
