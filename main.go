package main

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"sync"
	"syscall"
	"time"

	"aegisedge/filter"
	"aegisedge/logger"
	"aegisedge/manager"
	"aegisedge/middleware"
	"aegisedge/notifier"
	"aegisedge/proxy"
	"aegisedge/store"
	"aegisedge/util"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	pprof_handler "net/http/pprof"
)

func main() {
	// Runtime Tuning: Reduce GC frequency (200% = run GC half as often)
	// Trades ~2x memory for significantly lower CPU at high allocation rates.
	debug.SetGCPercent(200)
	runtime.GOMAXPROCS(runtime.NumCPU())

	configPath := "config.json"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		logger.Error("Failed to load config", "err", err)
		os.Exit(1)
	}

	// Apply configured log level if not overridden by env var
	if os.Getenv("AEGISEDGE_LOG_LEVEL") == "" && cfg.LogLevel != "" {
		logger.SetLevel(cfg.LogLevel)
	}

	logger.Info("Starting AegisEdge", "version", Version, "listen_ports", cfg.ListenPorts, "upstream", cfg.UpstreamAddr)

	// Initialize Storage (Local with Redis upgrade)
	var activeStore store.Storer = store.NewLocalStore()
	redisAddr := os.Getenv("AEGISEDGE_REDIS_ADDR")
	if redisAddr != "" {
		if rs := store.NewRedisStore(redisAddr, os.Getenv("AEGISEDGE_REDIS_PASSWORD")); rs != nil {
			activeStore = rs
			logger.Info("Distributed state initialized (Redis)", "addr", redisAddr)
		} else {
			logger.Error("Redis init failed — falling back to in-memory store", "addr", redisAddr)
		}
	} else {
		logger.Info("In-memory state initialized (Local fallback)")
	}

	// Initialize Reputation & Intelligence
	rep := filter.NewReputationManager(activeStore)

	// Initialize Filters
	l3 := filter.NewL3Filter(cfg.L3Blacklist, cfg.Whitelist)
	l4 := filter.NewL4Filter(cfg.L4ConnLimit, 5*time.Minute, activeStore, cfg.Whitelist)
	l7 := filter.NewL7Filter(cfg.L7RateLimit, cfg.L7BurstLimit, cfg.Whitelist)
	geoip := filter.NewGeoIPFilter(cfg.GeoIPDBPath, cfg.BlockedCountries)
	fingerprinter := filter.NewFingerprinter()
	anomaly := filter.NewAnomalyDetector([]string{"/search", "/api/heavy-export"}, 20, activeStore)
	stats := filter.NewStatisticalAnomalyDetector(60)

	// LiveToggles: reads toggle state at request time (not at startup),
	// so PATCH /api/config changes take effect immediately without restart.
	toggles := manager.NewLiveToggles(
		cfg.Toggles.WAF,
		cfg.Toggles.GeoIP,
		cfg.Toggles.Challenge,
		cfg.Toggles.Anomaly,
		cfg.Toggles.Stats,
	)

	// wrapToggle applies a middleware layer with a live-switchable toggle.
	// The middleware is pre-built at startup (wrapped and bypass), selected per request.
	// This is the correct pattern: toggle changes via /api/config take effect on the NEXT request.
	wrapToggle := func(name string, mw func(http.Handler) http.Handler) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			wrapped := mw(next) // pre-build the actual middleware chain
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if toggles.IsEnabled(name) {
					wrapped.ServeHTTP(w, r)
				} else {
					next.ServeHTTP(w, r) // bypass — skip this layer entirely
				}
			})
		}
	}

	// activeConns is an atomic counter for real load-aware challenge gating.
	var activeConns int64

	// Orchestration monitor & OS Hardening
	orchMonitor := filter.NewOrchestrationMonitor()
	orchMonitor.Start()
	filter.HardenOS()

	// Initialize Proxies (Default + Port-Specific)
	proxies := make(map[int]*proxy.ReverseProxy)
	defaultProxy, err := proxy.NewReverseProxy(cfg.UpstreamAddr)
	if err != nil {
		logger.Error("Failed to initialize default proxy", "err", err)
		os.Exit(1)
	}

	for portStr, target := range cfg.UpstreamMap {
		var pNum int
		fmt.Sscanf(portStr, "%d", &pNum)
		if prx, err := proxy.NewReverseProxy(target); err == nil {
			proxies[pNum] = prx
			logger.Info("Specialized upstream from map", "port", pNum, "target", target)
		}
	}

	// Zero-Config: For any listen_port NOT in the map, assume local loopback
	for _, port := range cfg.ListenPorts {
		if _, exists := proxies[port]; !exists {
			protocol := "http"
			if port == 443 {
				protocol = "https"
			}
			target := fmt.Sprintf("%s://127.0.0.1:%d", protocol, port)
			if prx, err := proxy.NewReverseProxy(target); err == nil {
				proxies[port] = prx
				logger.Info("Zero-Config upstream auto-discovery", "port", port, "target", target)
			}
		}
	}

	// ProxyWatcher: auto-discovers from CSF/cPHulk/iptables and merges with
	// the manual AEGISEDGE_TRUSTED_PROXY env var. Refreshes every 5 minutes.
	proxyWatcher := util.NewProxyWatcher(os.Getenv("AEGISEDGE_TRUSTED_PROXY"), 5*time.Minute)
	// Finding 4.2: flush the IP-resolution cache when the trusted-proxy
	// set changes so stale resolutions don't survive a reload.
	proxyWatcher.SetOnReloadHook(middleware.PurgeAllIPCache)
	logger.Info("Trusted proxy watcher started", "refresh_interval", "5m")

	// TCP PROXY Protocol trust: only watcher-trusted peers (or loopback)
	// may assert a PROXY header. Untrusted "PROXY ..." lines are ignored.
	filter.SetStreamProxyTrustCheck(proxyWatcher.IsTrusted)

	// Management API Instance
	mgmt := manager.NewManagementAPI(activeStore, toggles, proxyWatcher)
	mgmt.Version = Version
	notifier.SetUserAgent("AegisEdge/" + Version)

	// finalHandler: L3/L4 gate + Prometheus metrics + upstream proxy
	finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := util.GetRealIP(r)
		mgmt.TrackRequest()

		// Developer Whitelist Bypass (Absolute Precedence): skip L3/L4.
		if !l3.IsWhitelisted(host) {
			// Layer 3 (Centralized Block Check)
			if activeStore.IsBlocked(host) {
				logger.Warn("Blocked request: IP is in active block list", "remote_addr", host)
				if toggles.IsEnabled("stats") {
					filter.BlockedRequests.WithLabelValues("L3", "active_block").Inc()
				}
				http.Error(w, "Access Denied (Active Block)", http.StatusForbidden)
				return
			}

			if l3.IsBlacklisted(host) {
				logger.Warn("Blocked request: IP is blacklisted", "remote_addr", host)
				if toggles.IsEnabled("stats") {
					filter.BlockedRequests.WithLabelValues("L3", "blacklist").Inc()
				}
				http.Error(w, "Access Denied", http.StatusForbidden)
				return
			}

			// Layer 4 (uses the resolved client IP, not the TCP peer).
			// Hardened 2026-10-05: previously r.RemoteAddr (the load
			// balancer / CDN edge when behind a trusted proxy), which
			// lumped every client into one shared connection bucket —
			// a single abusive client tripped the cap for everyone and
			// per-attacker limiting did not exist. L3 above already
			// uses `host`; L4 must match.
			allowed, release := l4.AllowConnection(host)
			if !allowed {
				if toggles.IsEnabled("stats") {
					filter.BlockedRequests.WithLabelValues("L4", "conn_limit").Inc()
				}
				http.Error(w, "Too many connections", http.StatusServiceUnavailable)
				return
			}
			defer release()
		}

		// Dynamic Routing: Choose the upstream based on the port in the context
		targetProxy := defaultProxy
		if pVal := r.Header.Get("X-Aegis-Port"); pVal != "" {
			// Strict parse: WithPortInfo always writes %d, so anything
			// else is corruption — fall through to defaultProxy.
			if port, err := strconv.Atoi(pVal); err == nil {
				if specialized, exists := proxies[port]; exists {
					targetProxy = specialized
				}
			}
		}

		targetProxy.ServeHTTP(w, r)
	})


	// Build the inner security pipeline from inside out (innermost first).
	// Each wrapToggle layer can be switched on/off live via /api/config.
	inner := middleware.Tarpit(finalHandler, rep)
	inner = wrapToggle("waf", filter.WAFMiddleware)(inner)
	inner = wrapToggle("anomaly", anomaly.Middleware)(inner)
	inner = wrapToggle("stats", stats.Middleware)(inner)
	inner = wrapToggle("geoip", geoip.Middleware)(inner)
	inner = fingerprinter.Middleware(inner)                  // Fingerprinting always active
	inner = l7.Middleware(inner, rep)                        // Rate limiter + reputation

	// challengeInner: progressively challenges all unauthenticated traffic.
	// Builds the challenge around the inner pipeline once.
	challengeInner := middleware.ProgressiveChallenge(inner, rep)

	// attackChallenge: the outermost per-request decision gate.
	// Force challenge when:  (a) Z-Score anomaly detected, or (b) real concurrent load > 200.
	attackChallenge := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Outermost Load Tracking: Atomic core count is very fast, required for challenge logic
		atomic.AddInt64(&activeConns, 1)
		defer atomic.AddInt64(&activeConns, -1)

		// Prometheus Metrics: Gated behind "stats" toggle for 10k+ RPS efficiency
		if toggles.IsEnabled("stats") {
			filter.ActiveConnections.Inc()
			defer filter.ActiveConnections.Dec()

			timer := prometheus.NewTimer(filter.RequestLatency.WithLabelValues(r.Method, r.URL.Path))
			defer timer.ObserveDuration()
		}

		isUnderAttack := stats.IsUnderAttack()
		isHighLoad := atomic.LoadInt64(&activeConns) > 200

		if isUnderAttack || isHighLoad || toggles.IsEnabled("challenge") {
			challengeInner.ServeHTTP(w, r)
		} else {
			inner.ServeHTTP(w, r)
		}
	})

	// RealIP is the outermost layer — resolves the actual client IP from proxy
	// headers before any filter or middleware runs. List is updated live.
	securityStack := middleware.RealIP(proxyWatcher)(
		middleware.RequestLogger(
			middleware.SecurityHeaders(attackChallenge),
		),
	)

	// Fast-Reject Gate: The ABSOLUTE outermost handler.
	// Checks if an IP is already known-bad BEFORE entering ANY middleware.
	// This saves 8 middleware layers of CPU for every blocked request.
	stack := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract raw IP directly (RealIP middleware hasn't run yet)
		host, _, _ := net.SplitHostPort(r.RemoteAddr)

		// Ultra-fast path: If already soft-blocked by fingerprinter, reject instantly
		if filter.IsSoftBlocked(host) {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		// Check active block list (sharded store, very fast)
		if activeStore.IsBlocked(host) {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		securityStack.ServeHTTP(w, r)
	})

	// pprof endpoint for CPU profiling — loopback only. pprof exposes
	// goroutine stacks, heap contents and symbol tables; it must never
	// listen on 0.0.0.0. Override with AEGISEDGE_PPROF_BIND (dev only).
	pprofBind := getenvDefault("AEGISEDGE_PPROF_BIND", "127.0.0.1:6060")
	go func() {
		import_pprof_mux := http.NewServeMux()
		import_pprof_mux.HandleFunc("/debug/pprof/", pprof_handler.Index)
		import_pprof_mux.HandleFunc("/debug/pprof/cmdline", pprof_handler.Cmdline)
		import_pprof_mux.HandleFunc("/debug/pprof/profile", pprof_handler.Profile)
		import_pprof_mux.HandleFunc("/debug/pprof/symbol", pprof_handler.Symbol)
		import_pprof_mux.HandleFunc("/debug/pprof/trace", pprof_handler.Trace)
		logger.Info("pprof profiling active", "bind", pprofBind)
		http.ListenAndServe(pprofBind, import_pprof_mux)
	}()

	// Metrics endpoint
	metricsBind := getenvDefault("AEGISEDGE_METRICS_BIND", "127.0.0.1:9090")
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		logger.Info("Metrics engine active", "bind", metricsBind)
		http.ListenAndServe(metricsBind, mux)
	}()

	// Management API (Protected/Internal) — wired with LiveToggles for real-time config.
	// Binds loopback by default; set AEGISEDGE_MGMT_BIND to expose wider.
	// Set AEGISEDGE_DISABLE_MGMT=1 to not listen at all (lock-down).
	if os.Getenv("AEGISEDGE_DISABLE_MGMT") != "1" {
		go func() {
			mux := http.NewServeMux()
			mgmt.ServeHTTP(mux)
			mgmtBind := getenvDefault("AEGISEDGE_MGMT_BIND", "127.0.0.1:9091")
			logger.Info("Management API active", "bind", mgmtBind)
			http.ListenAndServe(mgmtBind, manager.APIKeyAuth(mux))
		}()
	} else {
		logger.Info("Management API disabled via AEGISEDGE_DISABLE_MGMT=1")
	}

	// Initialize Servers for all configured ports
	var servers []*http.Server
	hijackedPorts := make(map[int]int) // external -> internal

	for _, port := range cfg.ListenPorts {
		addr := fmt.Sprintf(":%d", port)
		idleTimeout := 60 * time.Second
		readTimeout := 15 * time.Second
		if cfg.HypervisorMode {
			logger.Info("Hypervisor optimized mode enabled", "port", port)
			idleTimeout = 300 * time.Second
			readTimeout = 30 * time.Second
		}

		srv := &http.Server{
			Addr:              addr,
			Handler:           WithPortInfo(port)(stack),
			ReadHeaderTimeout: 2 * time.Second,
			ReadTimeout:       readTimeout,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       idleTimeout,
		}

		isHTTPS := (port == 443)
		var cert, key string
		if isHTTPS {
			cert, key = cfg.DiscoverCerts()
			if cert == "" || key == "" {
				logger.Warn("Port 443 configured but SSL certificates could not be discovered. Falling back to HTTP.", "port", port)
				isHTTPS = false
			}
		}

		// Try to bind early to check status
		ln, err := net.Listen("tcp", srv.Addr)
		if err != nil && cfg.HotTakeover {
			logger.Warn("Port occupied, attempting Hot Takeover...", "port", port)
			// Start on any available port
			tempLn, tempErr := net.Listen("tcp", "127.0.0.1:0")
			if tempErr != nil {
				logger.Error("Failed to start ephemeral server for takeover", "err", tempErr)
				continue
			}
			
			internalPort := tempLn.Addr().(*net.TCPAddr).Port
			if err := filter.TakeoverPort(port, internalPort); err != nil {
				logger.Error("Hot Takeover failed", "port", port, "err", err)
				tempLn.Close()
				continue
			}
			hijackedPorts[port] = internalPort
			
			if isHTTPS {
				logger.Info("Hot Takeover active (HTTPS/L7 Protection)", "external", port, "internal", internalPort)
				go srv.ServeTLS(tempLn, cert, key)
			} else {
				logger.Info("Hot Takeover active (HTTP/L7 Protection)", "external", port, "internal", internalPort)
				go srv.Serve(tempLn)
			}
			servers = append(servers, srv)
			continue
		} else if err != nil {
			logger.Error("Failed to listen on port", "port", port, "err", err)
			os.Exit(1)
		}

		logger.Info("Proxy engine active", "addr", srv.Addr, "https", isHTTPS)
		servers = append(servers, srv)
		if isHTTPS {
			go srv.ServeTLS(ln, cert, key)
		} else {
			go srv.Serve(ln)
		}
	}

	// Initialize TCP Stream Protection for other ports (SSH, DB, etc.)
	for _, port := range cfg.TcpPorts {
		addr := fmt.Sprintf(":%d", port)
		targetAddr := fmt.Sprintf("127.0.0.1:%d", port)

		ln, err := net.Listen("tcp", addr)
		if err != nil && cfg.HotTakeover {
			logger.Warn("TCP Port occupied, attempting Hot Takeover...", "port", port)
			tempLn, tempErr := net.Listen("tcp", "127.0.0.1:0")
			if tempErr != nil {
				logger.Error("Failed to start ephemeral stream proxy", "err", tempErr)
				continue
			}

			internalPort := tempLn.Addr().(*net.TCPAddr).Port
			if err := filter.TakeoverPort(port, internalPort); err != nil {
				logger.Error("TCP Hot Takeover failed", "port", port, "err", err)
				tempLn.Close()
				continue
			}
			hijackedPorts[port] = internalPort
			
			go filter.StreamProxy(tempLn, targetAddr, l4)
			logger.Info("TCP Hot Takeover active (L4 Protection)", "external", port, "internal", internalPort)
			continue
		} else if err != nil {
			logger.Error("Failed to listen on TCP port", "port", port, "err", err)
			os.Exit(1)
		}

		logger.Info("TCP Stream Shield active", "port", port)
		go filter.StreamProxy(ln, targetAddr, l4)
	}

	// Graceful shutdown logic
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	<-done
	logger.Info("AegisEdge stopping... cleaning up resources")

	// Release Hijacked Ports
	for ext, internal := range hijackedPorts {
		filter.ReleasePort(ext, internal)
	}

	// Stop background cleanup loops and refresh goroutines
	l7.Stop()
	proxyWatcher.Stop()
	orchMonitor.Stop()
	if ls, ok := activeStore.(*store.LocalStore); ok {
		ls.Close()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	for _, srv := range servers {
		wg.Add(1)
		go func(s *http.Server) {
			defer wg.Done()
			// Don't log error here as some might already be closed via ln.Close()
			s.Shutdown(ctx)
		}(srv)
	}
	wg.Wait()

	logger.Info("All servers stopped gracefully")
}

// WithPortInfo wraps an http.Handler to inject the port into the headers.
func WithPortInfo(port int) func(http.Handler) http.Handler {
	portStr := fmt.Sprintf("%d", port)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Header.Set("X-Aegis-Port", portStr)
			next.ServeHTTP(w, r)
		})
	}
}

// getenvDefault returns os.Getenv(key) or def when unset/empty.
func getenvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
