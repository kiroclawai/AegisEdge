package filter

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"aegisedge/logger"
)

// OrchestrationMonitor watches L7 block counters and fires external
// automation (Ansible playbook, shell script, webhook) when thresholds
// are exceeded. Runs as a background goroutine with a configurable tick.
type OrchestrationMonitor struct {
	l7Threshold     int
	playbookPath    string
	playbookDir     string
	playbookTimeout time.Duration
	interval        time.Duration
	stop            chan struct{}
	wg              sync.WaitGroup
	lastTriggered   time.Time
	cooldown        time.Duration
	// inFlight (Finding 4.6) prevents overlapping playbook invocations.
	inFlight atomic.Bool
}

// orchestrationL7Blocks is an atomic counter incremented by the L7
// middleware whenever a request is blocked.
var orchestrationL7Blocks int64

// IncrementL7Blocks should be called by the L7 filter on every block.
func IncrementL7Blocks() {
	atomic.AddInt64(&orchestrationL7Blocks, 1)
}

// NewOrchestrationMonitor reads thresholds from environment and returns
// a monitor that can be started with .Start().
//
// Environment:
//   - ANSIBLE_TRIGGER_THRESHOLD_L7: L7 block count per window that triggers automation (default: off)
//   - ANSIBLE_PLAYBOOK_PATH: path to playbook/script to execute (default: off)
//   - ANSIBLE_PLAYBOOK_DIR: directory that the playbook path must live under (Finding 4.5)
//   - ANSIBLE_PLAYBOOK_TIMEOUT: seconds before a running playbook is killed (default: 30)
//   - ANSIBLE_CHECK_INTERVAL: seconds between checks (default: 60)
//   - ANSIBLE_COOLDOWN: seconds between consecutive triggers (default: 300)
func NewOrchestrationMonitor() *OrchestrationMonitor {
	threshold := 0
	if s := os.Getenv("ANSIBLE_TRIGGER_THRESHOLD_L7"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			threshold = n
		}
	}
	interval := 60 * time.Second
	if s := os.Getenv("ANSIBLE_CHECK_INTERVAL"); s != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 && n <= 3600 {
			interval = time.Duration(n) * time.Second
		}
	}
	cooldown := 300 * time.Second
	if s := os.Getenv("ANSIBLE_COOLDOWN"); s != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 && n <= 86400 {
			cooldown = time.Duration(n) * time.Second
		}
	}
	timeout := 30 * time.Second
	if s := os.Getenv("ANSIBLE_PLAYBOOK_TIMEOUT"); s != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 && n <= 300 {
			timeout = time.Duration(n) * time.Second
		}
	}
	return &OrchestrationMonitor{
		l7Threshold:     threshold,
		playbookPath:    os.Getenv("ANSIBLE_PLAYBOOK_PATH"),
		playbookDir:     os.Getenv("ANSIBLE_PLAYBOOK_DIR"),
		playbookTimeout: timeout,
		interval:        interval,
		stop:            make(chan struct{}),
		cooldown:        cooldown,
	}
}

// Start begins the background ticker. Call Stop to terminate.
func (m *OrchestrationMonitor) Start() {
	m.wg.Add(1)
	go m.loop()
}

// Stop signals the background ticker to exit and waits for it.
func (m *OrchestrationMonitor) Stop() {
	close(m.stop)
	m.wg.Wait()
}

func (m *OrchestrationMonitor) loop() {
	defer m.wg.Done()
	if m.l7Threshold <= 0 || m.playbookPath == "" {
		// Disabled: still consume the stop signal so Start/Stop contract holds.
		<-m.stop
		return
	}
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-ticker.C:
			m.check()
		}
	}
}

func (m *OrchestrationMonitor) check() {
	delta := atomic.SwapInt64(&orchestrationL7Blocks, 0)
	if delta < int64(m.l7Threshold) {
		return
	}
	if time.Since(m.lastTriggered) < m.cooldown {
		logger.Info("Orchestration: threshold exceeded but in cooldown",
			"delta", delta, "threshold", m.l7Threshold,
			"cooldown_remaining", m.cooldown-time.Since(m.lastTriggered),
		)
		return
	}
	// Finding 4.6: skip if a previous invocation is still running.
	if !m.inFlight.CompareAndSwap(false, true) {
		logger.Warn("Orchestration: skipping trigger — previous playbook still running",
			"delta", delta, "playbook", m.playbookPath,
		)
		return
	}
	defer m.inFlight.Store(false)

	logger.Warn("Orchestration: L7 threshold exceeded — executing playbook",
		"delta", delta, "threshold", m.l7Threshold, "playbook", m.playbookPath,
	)
	m.lastTriggered = time.Now()

	stdout, stderr, err := m.runPlaybook(delta)
	if err != nil {
		logger.Error("Orchestration: playbook execution failed",
			"err", err,
			"stdout", stdout.String(),
			"stderr", stderr.String(),
		)
		return
	}
	logger.Info("Orchestration: playbook executed successfully")
}

// runPlaybook executes m.playbookPath with a sanitized environment
// (Finding 4.5). Hardened 2026-09-25:
//   - Validates playbook path: must be absolute, must live under
//     ANSIBLE_PLAYBOOK_DIR if configured, must exist and be a regular file.
//   - Sanitizes environment: only PATH and the two documented variables
//     are passed; the parent process's os.Environ() (which contains
//     AEGISEDGE_API_KEY, REDIS_PASSWORD, webhook URLs, LD_PRELOAD, etc.)
//     is NEVER inherited.
//   - Runs under a context.WithTimeout so a hung playbook cannot leak
//     goroutines or wedge the orchestration monitor.
//   - Captures stdout/stderr to bounded buffers (4 KB each) so a
//     misbehaving playbook cannot OOM the proxy.
func (m *OrchestrationMonitor) runPlaybook(delta int64) (*bytes.Buffer, *bytes.Buffer, error) {
	// 1. Path validation.
	if !filepath.IsAbs(m.playbookPath) {
		return nil, nil, errors.New("playbook path must be absolute")
	}
	info, err := os.Stat(m.playbookPath)
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, errors.New("playbook path is not a regular file")
	}
	if m.playbookDir != "" {
		absDir, err := filepath.Abs(m.playbookDir)
		if err != nil {
			return nil, nil, err
		}
		absPlay, err := filepath.Abs(m.playbookPath)
		if err != nil {
			return nil, nil, err
		}
		rel, err := filepath.Rel(absDir, absPlay)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, nil, errors.New("playbook path escapes ANSIBLE_PLAYBOOK_DIR")
		}
	}

	// 2. Context with timeout.
	ctx, cancel := context.WithTimeout(context.Background(), m.playbookTimeout)
	defer cancel()

	// 3. Sanitized environment.
	cmd := exec.CommandContext(ctx, m.playbookPath)
	cmd.Env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"AEGISEDGE_L7_DELTA=" + strconv.FormatInt(delta, 10),
		"AEGISEDGE_L7_THRESHOLD=" + strconv.Itoa(m.l7Threshold),
	}

	// 4. Bounded output capture (4 KiB each — discard overflow).
	stdout := cappedBuffer{limit: 4096}
	stderr := cappedBuffer{limit: 4096}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return &stdout.buf, &stderr.buf, err
	}
	return &stdout.buf, &stderr.buf, nil
}

// cappedBuffer is a bounded bytes.Buffer-backed writer. Bytes past
// `limit` are discarded so a runaway playbook cannot OOM the proxy.
// The underlying buffer holds at most `limit` bytes.
type cappedBuffer struct {
	buf   bytes.Buffer
	limit int
	drop  int64
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	remaining := c.limit - c.buf.Len()
	if remaining <= 0 {
		c.drop += int64(len(p))
		return len(p), nil
	}
	if len(p) > remaining {
		n, _ := c.buf.Write(p[:remaining])
		c.drop += int64(len(p) - n)
		return len(p), nil
	}
	n, err := c.buf.Write(p)
	return n, err
}
