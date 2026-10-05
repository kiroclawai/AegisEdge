# AegisEdge — Operations Manual

This is the operator's guide. If you're reading this, AegisEdge is running and you need to control it. The management API runs on **port 9091** (keep it internal — never expose it to the internet). Prometheus metrics live on **port 9090**.

---

## Starting AegisEdge

```bash
# Default — reads config.json from the working directory
./aegisedge

# Custom config path
./aegisedge /etc/aegisedge/production.json

# With environment overrides (useful for containers and systemd)
AEGISEDGE_LOG_LEVEL=DEBUG AEGISEDGE_PORTS=80,443 ./aegisedge
```

A clean startup looks like this:

```
INFO  Starting AegisEdge listen_ports=[80,443] upstream=http://127.0.0.1:3000
INFO  In-memory state initialized (Local fallback)
INFO  Trusted proxy watcher started refresh_interval=5m
INFO  pprof profiling active port=6060
INFO  Metrics engine active port=9090
INFO  Management API active port=9091
```

If you see `GeoIP filter bypassed`, the `.mmdb` file is missing — everything else still runs.

---

## Configuration Hierarchy

Configuration is layered — each level wins over the one before it:

```
Hardcoded defaults  →  config.json  →  Environment variables
```

### config.json Reference

| Field | Type | Default | Description |
|---|---|---|---|
| `listen_ports` | `[]int` | `[8080]` | HTTP ports to bind |
| `tcp_ports` | `[]int` | `[]` | Raw TCP ports (SSH, DB, etc.) |
| `upstream_addr` | `string` | `localhost:3000` | Backend to proxy to |
| `l3_blacklist` | `[]string` | `[]` | Static IP/CIDR block list |
| `l4_conn_limit` | `int` | `0` (off) | Max concurrent connections per IP. **Set to 0 for zero-lock benchmarking.** |
| `l7_rate_limit` | `float64` | `0` | Token Bucket refill rate (req/sec) |
| `l7_burst_limit` | `int` | `0` | Token Bucket burst size |
| `log_level` | `string` | `INFO` | `DEBUG` / `INFO` / `WARN` / `ERROR`. WARN+ skips logging for successful requests. |
| `whitelist` | `[]string` | `[]` | IPs that bypass all security filters |
| `geoip_db_path` | `string` | `""` | Path to GeoLite2-Country.mmdb |
| `blocked_countries` | `[]string` | `[]` | ISO-3166 alpha-2 country codes |
| `hypervisor_mode` | `bool` | `false` | Tune for Proxmox/VMware/KVM |
| `hot_takeover` | `bool` | `false` | Hijack occupied ports via iptables |
| `ssl_cert_path` | `string` | auto-discover | TLS certificate |
| `ssl_key_path` | `string` | auto-discover | TLS private key |
| `toggles.waf` | `bool` | `true` | WAF inspection |
| `toggles.geoip` | `bool` | `true` | Country blocking |
| `toggles.challenge` | `bool` | `true` | JS challenge cookie |
| `toggles.anomaly` | `bool` | `true` | Heavy-URL anomaly detection |
| `toggles.stats` | `bool` | `true` | Statistical Z-score detector. **Disable for 10k+ RPS to avoid Prometheus overhead.** |

### Environment Variables

| Variable | Description |
|---|---|
| `AEGISEDGE_LOG_LEVEL` | `DEBUG` / `INFO` / `WARN` / `ERROR` |
| `AEGISEDGE_PORTS` | Comma-separated HTTP ports: `80,443,8080` |
| `AEGISEDGE_TCP_PORTS` | Comma-separated TCP ports: `22,3306,5432` |
| `AEGISEDGE_UPSTREAM` | Backend URL |
| `AEGISEDGE_HOT_TAKEOVER` | `true` to hijack occupied ports |
| `AEGISEDGE_HYPERVISOR_MODE` | `true` for VM environments |
| `AEGISEDGE_SSL_CERT` / `AEGISEDGE_SSL_KEY` | TLS paths |
| `AEGISEDGE_L4_CONN_LIMIT` | Connection cap per IP |
| `AEGISEDGE_L7_RATE_LIMIT` | Rate (req/sec) |
| `AEGISEDGE_L7_BURST_LIMIT` | Burst size |
| `AEGISEDGE_GEOIP_DB` | Path to .mmdb file |
| `AEGISEDGE_BLOCKED_COUNTRIES` | Comma-separated ISO codes |
| `AEGISEDGE_REDIS_ADDR` | Redis for cluster mode: `127.0.0.1:6379` |
| `AEGISEDGE_REDIS_PASSWORD` | Redis password |
| `AEGISEDGE_SECRET` | HMAC key for challenge cookies |
| `AEGISEDGE_WAF_BODY_MAX_BYTES` | WAF inspect cap in bytes (1024–4194304, default 65536) |
| `AEGISEDGE_DISABLE_MGMT` | `1` to not listen on the management API at all |
| `AEGISEDGE_MGMT_BIND` | Management API bind (default `127.0.0.1:9091`) |
| `AEGISEDGE_METRICS_BIND` | Prometheus bind (default `127.0.0.1:9090`) |
| `AEGISEDGE_PPROF_BIND` | pprof bind (default `127.0.0.1:6060`) — never expose |
| `AEGISEDGE_TRUSTED_PROXY` | Manual trusted proxy IPs/CIDRs (merged with auto-discovery) |
| `AEGISEDGE_WEBHOOK_URL` | Webhook URL for attack alerts (Slack, Discord, PagerDuty) |

---

## 🔧 Management API — Port 9091

### Check status

```bash
curl http://localhost:9091/api/status
```

---

### Block / Unblock an IP

```bash
# Temporary block
curl -X POST http://localhost:9091/api/block \
  -H "Content-Type: application/json" \
  -d '{"ip": "1.2.3.4", "duration": "1h"}'

# Permanent block
curl -X POST http://localhost:9091/api/block \
  -d '{"ip": "1.2.3.4", "duration": "permanent"}'

# Unblock
curl -X DELETE "http://localhost:9091/api/block?ip=1.2.3.4"
```

Supported durations: `30m`, `1h`, `24h`, `7d`, `permanent`

---

### Live Feature Toggles — no restart required

Toggle any security layer on the fly. The change takes effect on the **next request**.

```bash
PATCH /api/config
body: {"<toggle>": true|false}
```

```bash
# Disable WAF temporarily (e.g., debugging a false positive)
curl -X PATCH http://localhost:9091/api/config \
  -H "Content-Type: application/json" \
  -d '{"waf": false}'

# Force-enable challenge during an active attack
curl -X PATCH http://localhost:9091/api/config \
  -d '{"challenge": true}'
```

| Toggle key | Layer controlled |
|---|---|
| `waf` | Web Application Firewall |
| `geoip` | Country-based blocking |
| `challenge` | JS challenge cookie |
| `anomaly` | Heavy-URL + entropy detection |
| `stats` | Statistical Z-score detector |

---

### Trusted Proxy Whitelist — live, no restart

On a CSF/cPanel server, after editing `/etc/csf/csf.allow`, trigger an immediate reload:

```bash
# Force re-read of CSF/cPHulk/iptables right now
curl -X POST http://localhost:9091/api/proxy/reload

# Add a new CDN range at runtime
curl -X POST http://localhost:9091/api/proxy/add \
  -d '{"entry": "103.21.244.0/22"}'

# Remove an entry
curl -X DELETE "http://localhost:9091/api/proxy/remove?entry=103.21.244.0/22"
```

The watcher auto-refreshes every 5 minutes regardless — the manual reload is for when you can't wait.

---

## ⚡ Rate Limit Tuning

I set rate limits conservatively by default. Tune to your application's actual traffic profile:

```json
{
  "l7_rate_limit": 10.0,
  "l7_burst_limit": 20
}
```

- `l7_rate_limit` — the Token Bucket refill rate (requests/second per IP)
- `l7_burst_limit` — how many queued requests an IP can hold before being dropped

The reputation engine scales these automatically per IP. A client that has earned trust (score +10) gets **2×** the configured rate. A flagged client (score −5) gets **0.75×**. A hostile client (score −10) triggers kernel-level `iptables -j DROP` — the block goes below the application layer entirely.

---

## 🏁 Performance Tuning

### Configuration Presets

AegisEdge ships with three configuration presets in the `settings/` directory:

```bash
# Maximum throughput (benchmarking)
./aegisedge settings/performance.json

# Balanced security and performance
./aegisedge settings/standard.json

# Maximum security (active attack)
./aegisedge settings/aggressive.json
```

| Preset | WAF | GeoIP | Challenge | Stats | L4 Limit | Log Level |
|---|---|---|---|---|---|---|
| **Performance** | Off | Off | Off | Off | 0 (disabled) | WARN |
| **Standard** | On | On | On | On | 50 | INFO |
| **Aggressive** | On | On | On | On | 20 | DEBUG |

### Key Performance Knobs

| Setting | Impact | Recommendation |
|---|---|---|
| `log_level: "WARN"` | Skips logging for all 200 OK responses | **High impact** — eliminates 10k+ channel sends/sec |
| `stats: false` | Disables Prometheus histogram/gauge updates | **High impact** — removes per-request metric overhead |
| `l4_conn_limit: 0` | Disables L4 connection tracking entirely | **Medium impact** — zero-lock on connection accept |
| `waf: false` | Skips regex-based WAF inspection | **Medium impact** — saves regex CPU on every request |

### Runtime GC Tuning

AegisEdge sets `debug.SetGCPercent(200)` at startup, which halves Go's garbage collection frequency. This trades ~2× memory usage for significantly lower CPU under high allocation rates. To override:

```bash
GOGC=100 ./aegisedge settings/performance.json  # Default GC frequency
GOGC=400 ./aegisedge settings/performance.json  # Even less frequent GC
```

### Architecture: How AegisEdge Achieves Near-Zero Overhead

| Optimization | What It Does |
|---|---|
| **Fast-Reject Gate** | Blocks known-bad IPs before ANY middleware runs (microsecond rejection) |
| **64-Shard Storage** | Distributes lock contention across 64 independent shards |
| **G-Pattern** | Propagates metadata via headers instead of `context.WithValue` (zero allocations) |
| **IP Memoization** | Caches resolved IPs in a 64-shard cache, skipping header parsing on repeat requests |
| **Proxy Buffer Pool** | Recycles 32KB I/O buffers via `sync.Pool` |
| **Async Logging** | Log entries are buffered via channel, dropped if full (load-aware sampling) |

### CPU Profiling (pprof)

AegisEdge exposes a live CPU profiler on port `6060`:

```bash
# Capture a 10-second CPU profile
go tool pprof -top http://localhost:6060/debug/pprof/profile?seconds=10

# Interactive flame graph in browser
go tool pprof -http=:8081 http://localhost:6060/debug/pprof/profile?seconds=10

# Heap (memory) profile
go tool pprof -top http://localhost:6060/debug/pprof/heap
```

---

## 🌍 GeoIP Blocking

Get the free MaxMind GeoLite2 database and point AegisEdge at it:

```bash
AEGISEDGE_GEOIP_DB=/usr/share/GeoIP/GeoLite2-Country.mmdb
AEGISEDGE_BLOCKED_COUNTRIES=CN,RU,KP,IR
```

If the file isn't there, the filter skips gracefully — you'll see the warning in logs but nothing else breaks.

---

## 🎯 Challenge Cookie

When AegisEdge challenges a client:

1. Serves a JS page (HTTP 503) — browser runs the script
2. Browser GETs `?ae_token=<timestamp>.<HMAC-SHA256>`
3. Server validates the HMAC, sets `ae_clearance` (HttpOnly, 1 hour, **IP-bound**)
4. All subsequent requests from that browser pass silently

The IP-binding is intentional. A stolen cookie is useless from a different IP. Clients switching IPs (VPN, mobile handoff) re-challenge — this is a feature, not a bug.

Set your signing secret:
```bash
export AEGISEDGE_SECRET="your-long-random-secret-here"
```

---

## 📊 Prometheus Metrics — Port 9090

```bash
curl http://localhost:9090/metrics
```

Key metrics (all prefixed `aegisedge_`):
```
aegisedge_blocked_requests_total{layer="L3|L4|L7", reason="..."}
aegisedge_active_connections   (gauge — current in-flight requests)
aegisedge_request_duration_seconds{method, path}   (histogram — latency per endpoint)
```

Example Grafana alert for block rate > 100/min:
```promql
rate(aegisedge_blocked_requests_total[1m]) * 60 > 100
```

P99 latency alert:
```promql
histogram_quantile(0.99, rate(aegisedge_request_duration_seconds_bucket[5m])) > 0.5
```

---

## � Webhook Alerts

AegisEdge can push attack notifications to any webhook endpoint (Slack, Discord, PagerDuty, custom). Set the URL and forget — alerts fire asynchronously in a goroutine so they never add latency to requests.

```bash
export AEGISEDGE_WEBHOOK_URL="https://hooks.slack.com/services/T.../B.../xxx"
```

Payload format:
```json
{
  "text": "[AegisEdge Alert] VOLUMETRIC ATTACK DETECTED: RPS hit 450.00 (3-Sigma Threshold: 38.50)",
  "timestamp": "2026-02-24T16:45:00Z",
  "severity": "CRITICAL"
}
```

If `AEGISEDGE_WEBHOOK_URL` isn't set, the notifier is a no-op — no errors, no overhead.

---

## ⚡ High-Load Auto-Challenge

Beyond the Z-Score statistical detector, AegisEdge has a second safety net: when concurrent in-flight connections exceed **200**, the JS challenge is force-enabled for all traffic — regardless of the challenge toggle or anomaly detector state. This catches slow-burn attacks that stay under the statistical threshold but still exhaust backend resources.

This is hardcoded in `main.go` and always active. You don't need to configure anything.

---


## 📋 Log Reference

AegisEdge emits structured JSON. Every line has `time`, `level`, `msg`, and relevant fields.

| Level | Message | Meaning |
|---|---|---|
| `INFO` | `Starting AegisEdge` | Startup, shows active ports and upstream |
| `INFO` | `Trusted proxy watcher started` | Background refresh goroutine started |
| `INFO` | `PROXY Protocol: resolved real client IP` | TCP stream IP extracted from PROXY header |
| `WARN` | `L7 rate limit exceeded (token bucket)` | IP throttled — shows effective rate |
| `WARN` | `WAF blocked request` | Shows pattern and field (query/body/path) |
| `WARN` | `Blocked request from unauthorized country` | GeoIP match |
| `WARN` | `Anomaly detected: High frequency on heavy URL` | Repeated hammering of heavy endpoints |
| `WARN` | `Anomaly detected: Behavioral lock-on` | Low-entropy request pattern (bot-like) |
| `WARN` | `Invalid challenge cookie signature or IP mismatch` | Cookie tampered or IP changed |
| `WARN` | `Tarpitting suspicious request` | Shows the delay in ms |
| `WARN` | `L4 stream connection rejected` | TCP flood past connection cap |
| `ERROR` | `Failed to load config` | Config file parse error — check JSON |

Adjust verbosity on the fly by restarting with `AEGISEDGE_LOG_LEVEL=DEBUG` during an incident. Switch back to `INFO` after — debug logs are verbose under load.

---

## 🔌 Hot Takeover

Enable this if you're running Apache or Nginx on port 80/443 and want to insert AegisEdge without a maintenance window:

```bash
AEGISEDGE_HOT_TAKEOVER=true ./aegisedge
```

AegisEdge uses `iptables PREROUTING REDIRECT` to intercept the port before the original service sees the packet. The existing service keeps running unchanged. On shutdown, the REDIRECT rule is removed and the original service reclaims its port.

Requires root or `CAP_NET_ADMIN`.

---

## 🌊 TCP Port Shielding

Protect raw TCP ports with per-IP connection limiting:

```json
{
  "tcp_ports": [22, 3306, 5432]
}
```

If your upstream is HAProxy or AWS NLB and it sends PROXY Protocol headers, AegisEdge strips the header automatically and applies rate limits to the **real client IP**, not the load balancer.

HAProxy config for this:
```
server backend 10.0.0.1:22 send-proxy
```

---

## 🗄️ Redis Cluster Mode

Share state across multiple AegisEdge nodes:

```bash
AEGISEDGE_REDIS_ADDR=10.0.0.5:6379 \
AEGISEDGE_REDIS_PASSWORD=yourpassword \
./aegisedge
```

I use LUA scripts for atomic increments — no race conditions under concurrent flood. The system falls back to local in-memory state transparently if Redis goes down.

---

## 🔐 TLS / HTTPS

I built auto-discovery so you don't have to touch SSL config on cPanel or Let's Encrypt servers. The discovery order:

1. `AEGISEDGE_SSL_CERT` / `AEGISEDGE_SSL_KEY` env vars
2. `ssl_cert_path` / `ssl_key_path` in config.json
3. `certs/cert.pem` + `certs/key.pem` (local directory)
4. Let's Encrypt: `/etc/letsencrypt/live/*/fullchain.pem`
5. cPanel/WHM: `/var/cpanel/ssl/installed/certs/*.crt`
6. Plesk: `/usr/local/psa/var/certificates/*`
7. System fallback: `/etc/ssl/certs/aegis.crt`

To be explicit:
```bash
AEGISEDGE_SSL_CERT=/etc/letsencrypt/live/example.com/fullchain.pem \
AEGISEDGE_SSL_KEY=/etc/letsencrypt/live/example.com/privkey.pem \
./aegisedge
```

---

## 🛑 Graceful Shutdown

Send `SIGTERM` or hit `Ctrl+C`. AegisEdge will:

1. Stop accepting new connections
2. Drain in-flight requests (10-second window)
3. Stop background goroutines: L7 cleanup, ProxyWatcher refresh, LocalStore expiry
4. Release iptables rules from Hot Takeover ports
5. Log `All servers stopped gracefully`

```bash
kill -TERM $(pgrep aegisedge)
```

---

## 🔍 Troubleshooting

**"All traffic is blocked"**
- Run with `AEGISEDGE_LOG_LEVEL=DEBUG` and watch the `remote_addr` field in WARN logs
- If it's your CDN or LB IP instead of the real client → trusted proxy not configured
- Run `curl -X POST localhost:9091/api/proxy/reload` or set `AEGISEDGE_TRUSTED_PROXY`

**"Challenge never clears"**
- Is `AEGISEDGE_SECRET` set? Without it, HMAC mismatches on every verify
- Client switching IPs? That re-triggers challenge by design
- Clock drift? Cookie TTL is 1 hour — validate server time with `date`

**"GeoIP not blocking"**
- Check the `.mmdb` file exists and is readable
- Look for `GeoIP filter bypassed` in startup logs
- Confirm `toggles.geoip: true` or PATCH it on via API

**"Rate limits too aggressive"**
- Check the reputation score for the affected IP — it may have been penalised
- Review `effective_rate` in the WARN log line to see what multiplier was applied
- Temporarily disable: `curl -X PATCH localhost:9091/api/config -d '{"challenge": false}'`

**"Port already in use"**
```bash
AEGISEDGE_HOT_TAKEOVER=true ./aegisedge
```

**"High CPU during attack"**
- Use `settings/performance.json` for maximum throughput (disables WAF, GeoIP, Stats, Challenge)
- The **Fast-Reject Gate** blocks known-bad IPs before any middleware runs — CPU savings scale with attack volume
- Most CPU (85%) is Go's `net/http` server and kernel syscalls, not AegisEdge code — use `pprof` to verify:
  ```bash
  go tool pprof -top http://localhost:6060/debug/pprof/profile?seconds=10
  ```
- Block high-volume attackers at L3 via API — they'll hit `iptables DROP` before reaching Go:
  ```bash
  curl -X POST localhost:9091/api/block -d '{"ip": "1.2.3.4", "duration": "permanent"}'
  ```
- Set `GOGC=400` for even less frequent garbage collection at the cost of more RAM
