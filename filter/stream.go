package filter

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"aegisedge/logger"
)

// streamDataTimeout is applied to the data-plane io.Copy loops so a
// slowloris-style client cannot hold the goroutine and the upstream
// socket forever. Hardened 2026-09-25 per Finding 2.4.
// Operators can override via AEGISEDGE_STREAM_DATA_TIMEOUT.
var streamDataTimeout = 60 * time.Second

// streamProxyTrustCheck decides whether the immediate TCP peer is allowed
// to assert a PROXY Protocol header. Nil = trust loopback only.
// Set via SetStreamProxyTrustCheck (main.go wires the ProxyWatcher).
// Hardened 2026-10-04: previously ANY direct client could prepend
// "PROXY TCP4 <victim-ip> ..." and choose its own rate-limit identity
// (bucket-splitting past L4 caps, or framing an innocent IP).
var streamProxyTrustCheck func(peerHost string) bool

// SetStreamProxyTrustCheck installs the PROXY-protocol trust predicate.
// Pass nil to reset to loopback-only.
func SetStreamProxyTrustCheck(fn func(peerHost string) bool) {
	streamProxyTrustCheck = fn
}

func streamPeerTrusted(peerHost string) bool {
	if ip := net.ParseIP(peerHost); ip != nil && ip.IsLoopback() {
		return true
	}
	if streamProxyTrustCheck != nil {
		return streamProxyTrustCheck(peerHost)
	}
	return false
}

// StreamProxy provides L4 protection for non-HTTP protocols.
// It supports PROXY Protocol v1 so that the real client IP is used
// for connection limiting when behind a TCP load balancer (HAProxy, AWS NLB).
func StreamProxy(ln net.Listener, targetAddr string, l4 *L4Filter) {
	for {
		clientConn, err := ln.Accept()
		if err != nil {
			logger.Error("Stream proxy accept error", "err", err)
			return
		}

		go handleStream(clientConn, targetAddr, l4)
	}
}

func handleStream(conn net.Conn, targetAddr string, l4 *L4Filter) {
	defer conn.Close()

	// PROXY Protocol is honored ONLY when the immediate peer is trusted
	// (loopback or ProxyWatcher-trusted). Untrusted peers get their
	// first line replayed verbatim — a forged "PROXY ..." line becomes
	// upstream garbage, not a spoofed identity.
	peerHost, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		peerHost = conn.RemoteAddr().String()
	}
	trusted := streamPeerTrusted(peerHost)

	// Peek at the first line to detect a PROXY Protocol v1 header.
	br := bufio.NewReader(conn)
	realAddr, reader := resolveProxyProtocol(br, conn, trusted)

	allowed, release := l4.AllowConnection(realAddr)
	if !allowed {
		logger.Warn("L4 stream connection rejected", "addr", realAddr)
		return
	}
	defer release()

	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// Mark packets on Linux/WSL only (SO_MARK = 36)
				if runtime.GOOS == "linux" {
					syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 36, 0xAE615)
				}
			})
		},
	}

	targetConn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		logger.Error("Stream proxy dial error", "addr", targetAddr, "err", err)
		return
	}
	defer targetConn.Close()

	// Finding 2.4: enforce data-plane idle timeout. We refresh the
	// read deadline on every successful chunk via a wrapper reader,
	// so an actively-used connection never times out but an idle one
	// (slowloris, half-open client) tears down within streamDataTimeout.
	idleTimeout := streamDataTimeout
	if l4 != nil && l4.IdleTimeout > 0 {
		idleTimeout = l4.IdleTimeout
	}

	var stopWatchdog atomic.Bool
	watchdog := time.AfterFunc(idleTimeout, func() {
		stopWatchdog.Store(true)
		_ = conn.SetReadDeadline(time.Now())
		_ = targetConn.SetReadDeadline(time.Now())
	})
	defer watchdog.Stop()

	src := newDeadlineRefresher(reader, conn, idleTimeout, watchdog)
	dst := newDeadlineRefresher(targetConn, targetConn, idleTimeout, watchdog)

	done := make(chan struct{}, 2)
	go func() {
		io.Copy(dst, src)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(src, dst)
		done <- struct{}{}
	}()
	<-done
	if stopWatchdog.Load() {
		logger.Warn("Stream proxy: connection idle timeout", "addr", realAddr, "idle_timeout", idleTimeout)
	}
}

// deadlineRefresher wraps a read/write pair and resets a *time.Timer
// on every successful Read or Write. The timer fires after the configured
// idle duration and forces the underlying connection's read deadline
// to "now", which makes io.Copy return with a timeout error and the
// proxy tears the connection down.
type deadlineRefresher struct {
	r       io.Reader
	w       io.Writer
	timeout time.Duration
	timer   *time.Timer
}

func newDeadlineRefresher(r io.Reader, w io.Writer, timeout time.Duration, timer *time.Timer) *deadlineRefresher {
	return &deadlineRefresher{
		r:       r,
		w:       w,
		timeout: timeout,
		timer:   timer,
	}
}

func (d *deadlineRefresher) Read(p []byte) (int, error) {
	n, err := d.r.Read(p)
	if n > 0 && d.timer != nil {
		d.timer.Reset(d.timeout)
	}
	return n, err
}

func (d *deadlineRefresher) Write(p []byte) (int, error) {
	n, err := d.w.Write(p)
	if n > 0 && d.timer != nil {
		d.timer.Reset(d.timeout)
	}
	return n, err
}

// resolveProxyProtocol peeks at the connection for a PROXY Protocol v1 header.
// Format: "PROXY TCP4 <src-ip> <dst-ip> <src-port> <dst-port>\r\n"
// Returns the resolved address string and an io.Reader that replays all bytes.
// When trusted is false the header is NEVER honored: the peeked line is
// replayed verbatim so a forged header cannot spoof the L4 identity.
func resolveProxyProtocol(br *bufio.Reader, conn net.Conn, trusted bool) (string, io.Reader) {
	fallback := conn.RemoteAddr().String()

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	line, err := br.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "PROXY ") {
		return fallback, io.MultiReader(strings.NewReader(line), br)
	}
	if !trusted {
		logger.Warn("PROXY header from untrusted peer — ignoring", "peer", fallback)
		return fallback, io.MultiReader(strings.NewReader(line), br)
	}

	parts := strings.Fields(line)
	if len(parts) < 6 || (parts[1] != "TCP4" && parts[1] != "TCP6") {
		return fallback, br
	}

	srcIP := parts[2]
	if net.ParseIP(srcIP) == nil {
		return fallback, br
	}
	srcPort := parts[4]
	if p, err := strconv.Atoi(srcPort); err != nil || p < 1 || p > 65535 {
		return fallback, br
	}
	realAddr := fmt.Sprintf("%s:%s", srcIP, srcPort)

	logger.Info("PROXY Protocol: resolved real client IP", "real_addr", realAddr, "proxy_addr", conn.RemoteAddr())
	return realAddr, br
}
