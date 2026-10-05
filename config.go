package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenPort       int          `json:"listen_port"` // Legacy support
	ListenPorts      []int        `json:"listen_ports"`
	TcpPorts         []int             `json:"tcp_ports"`
	UpstreamAddr     string            `json:"upstream_addr"`
	UpstreamMap      map[string]string `json:"upstream_map"`
	L3Blacklist      []string          `json:"l3_blacklist"`
	Whitelist        []string          `json:"whitelist"`
	L4ConnLimit      int          `json:"l4_conn_limit"`
	L7RateLimit      float64      `json:"l7_rate_limit"`
	L7BurstLimit     int          `json:"l7_burst_limit"`
	GeoIPDBPath      string       `json:"geoip_db_path"`
	BlockedCountries []string     `json:"blocked_countries"`
	HypervisorMode   bool         `json:"hypervisor_mode"`
	HotTakeover      bool         `json:"hot_takeover"`
	SSLCertPath      string       `json:"ssl_cert_path"`
	SSLKeyPath       string            `json:"ssl_key_path"`
	LogLevel         string            `json:"log_level"`
	Toggles          FeatureFlags      `json:"toggles"`
}

type FeatureFlags struct {
	WAF       bool `json:"waf"`
	GeoIP     bool `json:"geoip"`
	Challenge bool `json:"challenge"`
	Anomaly   bool `json:"anomaly"`
	Stats     bool `json:"stats"`
}

// Validate rejects configuration values that would silently disable
// AegisEdge's protection or cause resource exhaustion. Hardened
// 2026-09-25 per Findings 2.7 (unvalidated floats / ints) and 4.3
// (fmt.Sscanf-based trust parsing replaced with strict strconv).
// Called by LoadConfig before returning; a bad config aborts startup.
func (c *Config) Validate() error {
	if math.IsNaN(c.L7RateLimit) || math.IsInf(c.L7RateLimit, 0) || c.L7RateLimit < 0 {
		return fmt.Errorf("l7_rate_limit must be a finite non-negative number, got %v", c.L7RateLimit)
	}
	if c.L7RateLimit > 1e9 {
		return fmt.Errorf("l7_rate_limit suspiciously large: %v (>1e9)", c.L7RateLimit)
	}
	if c.L4ConnLimit < 0 {
		return fmt.Errorf("l4_conn_limit must be >= 0, got %d", c.L4ConnLimit)
	}
	if c.L7BurstLimit < 0 {
		return fmt.Errorf("l7_burst_limit must be >= 0, got %d", c.L7BurstLimit)
	}
	if c.ListenPort < 0 || c.ListenPort > 65535 {
		return fmt.Errorf("listen_port out of range: %d", c.ListenPort)
	}
	for i, p := range c.ListenPorts {
		if p < 0 || p > 65535 {
			return fmt.Errorf("listen_ports[%d] out of range: %d", i, p)
		}
	}
	for i, p := range c.TcpPorts {
		if p < 1 || p > 65535 {
			return fmt.Errorf("tcp_ports[%d] out of range: %d", i, p)
		}
	}
	if c.UpstreamAddr != "" {
		u, err := url.Parse(c.UpstreamAddr)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("upstream_addr must be a valid http(s) URL, got %q", c.UpstreamAddr)
		}
	}
	for name, addr := range c.UpstreamMap {
		u, err := url.Parse(addr)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("upstream_map[%q] must be a valid http(s) URL, got %q", name, addr)
		}
	}
	for i, s := range c.L3Blacklist {
		if !isValidIPOrCIDR(s) {
			return fmt.Errorf("l3_blacklist[%d] not a valid IP/CIDR: %q", i, s)
		}
	}
	for i, s := range c.Whitelist {
		if !isValidIPOrCIDR(s) {
			return fmt.Errorf("whitelist[%d] not a valid IP/CIDR: %q", i, s)
		}
	}
	if c.GeoIPDBPath != "" {
		// Missing file is NOT fatal: NewGeoIPFilter degrades gracefully
		// (logs "GeoIP filter bypassed") so a rotated/deleted .mmdb must
		// never prevent startup. Only reject paths that exist but are
		// directories, which indicates a mount misconfiguration.
		if fi, err := os.Stat(c.GeoIPDBPath); err == nil && fi.IsDir() {
			return fmt.Errorf("geoip_db_path is a directory, want a .mmdb file: %q", c.GeoIPDBPath)
		}
	}
	for i, cc := range c.BlockedCountries {
		if len(cc) != 2 {
			return fmt.Errorf("blocked_countries[%d] must be a 2-letter ISO code, got %q", i, cc)
		}
		for _, r := range cc {
			if r < 'A' || r > 'Z' {
				return fmt.Errorf("blocked_countries[%d] must be uppercase, got %q", i, cc)
			}
		}
	}
	return nil
}

func isValidIPOrCIDR(s string) bool {
	if s == "" {
		return false
	}
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err == nil
	}
	return net.ParseIP(s) != nil
}

func LoadConfig(path string) (*Config, error) {
	// 1. Set System Defaults
	cfg := Config{
		UpstreamAddr: "http://localhost:3000",
		ListenPorts:  []int{8080},
		Toggles: FeatureFlags{
			WAF:       true,
			GeoIP:     true,
			Challenge: true,
			Anomaly:   true,
			Stats:     true,
		},
	}
	
	// 2. Load from file (Overrides Defaults)
	if _, err := os.Stat(path); err != nil {
		if path != "config.json" {
			return nil, fmt.Errorf("config file not found: %s", path)
		}
		// Default config.json missing is okay, use defaults
	} else {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		decoder := json.NewDecoder(file)
		if err := decoder.Decode(&cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config %s: %v", path, err)
		}
	}

	// Handle legacy port synchronization
	if len(cfg.ListenPorts) == 0 && cfg.ListenPort != 0 {
		cfg.ListenPorts = []int{cfg.ListenPort}
	}

	// 3. Load from Environment (Overrides File)
	if val := os.Getenv("AEGISEDGE_PORT"); val != "" {
		if p, err := strconv.Atoi(strings.TrimSpace(val)); err != nil {
			return nil, fmt.Errorf("AEGISEDGE_PORT not a valid integer: %q", val)
		} else if p < 1 || p > 65535 {
			return nil, fmt.Errorf("AEGISEDGE_PORT out of range: %d", p)
		} else {
			cfg.ListenPorts = append(cfg.ListenPorts, p)
		}
	}
	if val := os.Getenv("AEGISEDGE_PORTS"); val != "" {
		portStrs := strings.Split(val, ",")
		for _, s := range portStrs {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			p, err := strconv.Atoi(s)
			if err != nil {
				return nil, fmt.Errorf("AEGISEDGE_PORTS entry not a valid integer: %q", s)
			}
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("AEGISEDGE_PORTS entry out of range: %d", p)
			}
			cfg.ListenPorts = append(cfg.ListenPorts, p)
		}
	}
	if val := os.Getenv("AEGISEDGE_TCP_PORTS"); val != "" {
		portStrs := strings.Split(val, ",")
		for _, s := range portStrs {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			p, err := strconv.Atoi(s)
			if err != nil {
				return nil, fmt.Errorf("AEGISEDGE_TCP_PORTS entry not a valid integer: %q", s)
			}
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("AEGISEDGE_TCP_PORTS entry out of range: %d", p)
			}
			cfg.TcpPorts = append(cfg.TcpPorts, p)
		}
	}
	if val := os.Getenv("AEGISEDGE_UPSTREAM"); val != "" {
		cfg.UpstreamAddr = val
	}
	if val := os.Getenv("AEGISEDGE_HYPERVISOR_MODE"); val != "" {
		cfg.HypervisorMode = (val == "true" || val == "1")
	}
	if val := os.Getenv("AEGISEDGE_HOT_TAKEOVER"); val != "" {
		cfg.HotTakeover = (val == "true" || val == "1")
	}
	if val := os.Getenv("AEGISEDGE_SSL_CERT"); val != "" {
		cfg.SSLCertPath = val
	}
	if val := os.Getenv("AEGISEDGE_SSL_KEY"); val != "" {
		cfg.SSLKeyPath = val
	}
	if val := os.Getenv("AEGISEDGE_L4_CONN_LIMIT"); val != "" {
		// Hardened 2026-09-25 per Finding 4.3: use strconv (strict)
		// instead of fmt.Sscanf (silent on garbage input).
		n, err := strconv.Atoi(val)
		if err != nil {
			return nil, fmt.Errorf("AEGISEDGE_L4_CONN_LIMIT not a valid integer: %q", val)
		}
		cfg.L4ConnLimit = n
	}
	if val := os.Getenv("AEGISEDGE_L7_RATE_LIMIT"); val != "" {
		f, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return nil, fmt.Errorf("AEGISEDGE_L7_RATE_LIMIT not a valid float: %q", val)
		}
		cfg.L7RateLimit = f
	}
	if val := os.Getenv("AEGISEDGE_L7_BURST_LIMIT"); val != "" {
		n, err := strconv.Atoi(val)
		if err != nil {
			return nil, fmt.Errorf("AEGISEDGE_L7_BURST_LIMIT not a valid integer: %q", val)
		}
		cfg.L7BurstLimit = n
	}
	if val := os.Getenv("AEGISEDGE_GEOIP_DB"); val != "" {
		cfg.GeoIPDBPath = val
	}
	if val := os.Getenv("AEGISEDGE_BLOCKED_COUNTRIES"); val != "" {
		parts := strings.Split(val, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.ToUpper(strings.TrimSpace(p))
			if p != "" {
				out = append(out, p)
			}
		}
		cfg.BlockedCountries = out
	}

	// Hardened 2026-09-25 per Finding 2.7: refuse to start with bad config.
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}
	return &cfg, nil
}

// DiscoverCerts attempts to find SSL certificates in common system
// locations. Hardened 2026-09-25 per Finding 3.2:
//
//   - All candidate (cert, key) pairs are collected first.
//   - Expired pairs are skipped (the previous code returned the first
//     matching pair without checking expiry).
//   - Among valid pairs, the one with the latest NotAfter is preferred
//     so a newly-rotated cert wins over a long-lived legacy cert in the
//     same glob pattern.
//   - Cert/key basenames must match (prevents "cert.pem" pairing with
//     "another-key.pem" from a different cert in the same directory).
//   - Hot reload via fsnotify is supported when fsnotify is available;
//     see StartCertWatcher.
func (c *Config) DiscoverCerts() (string, string) {
	if c.SSLCertPath != "" && c.SSLKeyPath != "" {
		// Explicit paths: still validate expiry; refuse to serve an
		// expired cert unless AEGISEDGE_ALLOW_EXPIRED_CERTS=1.
		if !allowExpiredCerts() {
			if exp, err := certNotAfter(c.SSLCertPath); err == nil && time.Now().After(exp) {
				return "", ""
			}
		}
		return c.SSLCertPath, c.SSLKeyPath
	}

	searches := []struct {
		certPattern string
		keyPattern  string
	}{
		{"certs/cert.pem", "certs/key.pem"},
		{"/etc/letsencrypt/live/*/fullchain.pem", "/etc/letsencrypt/live/*/privkey.pem"},
		{"/etc/letsencrypt/open/fullchain.pem", "/etc/letsencrypt/open/privkey.pem"},
		{"/etc/ssl/certs/aegis.crt", "/etc/ssl/private/aegis.key"},
		{"/etc/pki/tls/certs/localhost.crt", "/etc/pki/tls/private/localhost.key"},
		// cPanel / WHM
		{"/var/cpanel/ssl/installed/certs/*.crt", "/var/cpanel/ssl/installed/keys/*.key"},
		// Plesk
		{"/usr/local/psa/var/certificates/*", "/usr/local/psa/var/certificates/*"},
	}

	allowExpired := allowExpiredCerts()
	type candidate struct {
		cert     string
		key      string
		notAfter time.Time
	}
	var candidates []candidate
	seen := make(map[string]bool)

	for _, s := range searches {
		certs, _ := filepath.Glob(s.certPattern)
		for _, cert := range certs {
			if seen[cert] {
				continue
			}
			keys, _ := filepath.Glob(s.keyPattern)
			for _, key := range keys {
				if filepath.Base(cert) != filepath.Base(key) {
					continue // cert/key must match by basename
				}
				if _, err := os.Stat(cert); err != nil {
					continue
				}
				if _, err := os.Stat(key); err != nil {
					continue
				}
				exp, err := certNotAfter(cert)
				if err != nil {
					continue // unparseable: skip
				}
				if !allowExpired && time.Now().After(exp) {
					continue // expired: skip
				}
				candidates = append(candidates, candidate{cert: cert, key: key, notAfter: exp})
				seen[cert] = true
				break
			}
		}
	}

	if len(candidates) == 0 {
		return "", ""
	}
	// Prefer the most-recently-expiring cert (the freshest one wins).
	best := candidates[0]
	for _, c := range candidates[1:] {
		if c.notAfter.After(best.notAfter) {
			best = c
		}
	}
	return best.cert, best.key
}

// allowExpiredCerts lets an operator keep a proxy running on an expired
// cert (useful for staging or behind another terminator). Default off.
func allowExpiredCerts() bool {
	return os.Getenv("AEGISEDGE_ALLOW_EXPIRED_CERTS") == "1"
}

// certNotAfter reads a PEM-encoded cert and returns its NotAfter time.
// Hardened 2026-09-25: previously the cert path was returned without
// any inspection of validity, so an expired cert could be served
// indefinitely (Finding 3.2).
func certNotAfter(path string) (time.Time, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return time.Time{}, fmt.Errorf("no PEM block in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}
