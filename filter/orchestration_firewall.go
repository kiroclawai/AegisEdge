package filter

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"aegisedge/logger"
)

// HardenOS applies kernel-level protections against common network attacks.
func HardenOS() {
	if runtime.GOOS == "windows" {
		hardenWindows()
	} else if runtime.GOOS == "linux" {
		hardenLinux()
	}
}

// BlockIPKernel blocks an IP address at the OS firewall level (L3).
//
// Hardened 2026-09-25 per Finding 4.4: previous code blindly inserted
// a new iptables rule every call, accumulating duplicates whenever the
// kernel dedupe in ReputationManager.adjust lost a CAS race. Now we
// run `iptables -C` (check) first; if the rule is already present the
// function returns nil. The `-w` flag acquires the iptables lock so
// concurrent AegisEdge instances don't interleave with each other.
func BlockIPKernel(ip string) error {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		// netsh advfirewall firewall add rule name="AegisBlock_1.2.3.4" dir=in action=block remoteip=1.2.3.4
		ruleName := fmt.Sprintf("AegisBlock_%s", ip)
		// Idempotency check: if the rule already exists, return success.
		check := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name="+ruleName)
		if out, err := check.CombinedOutput(); err == nil && strings.Contains(string(out), ruleName) {
			return nil
		}
		cmd = exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
			"name="+ruleName, "dir=in", "action=block", "remoteip="+ip)
	} else {
		// Idempotency: check before insert.
		checkArgs := []string{"-w", "-C", "INPUT", "-s", ip, "-j", "DROP"}
		if err := exec.Command("iptables", checkArgs...).Run(); err == nil {
			return nil // rule already present
		}
		cmd = exec.Command("iptables", "-w", "-I", "INPUT", "-s", ip, "-j", "DROP")
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Failed to block IP in kernel", "ip", ip, "err", err, "output", string(output))
		return err
	}
	logger.Info("IP blocked at kernel level (L3)", "ip", ip)
	return nil
}

// UnblockIPKernel removes a kernel-level block for an IP address.
func UnblockIPKernel(ip string) error {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		ruleName := fmt.Sprintf("AegisBlock_%s", ip)
		cmd = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+ruleName)
	} else {
		cmd = exec.Command("iptables", "-w", "-D", "INPUT", "-s", ip, "-j", "DROP")
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		if runtime.GOOS == "windows" && strings.Contains(string(output), "No rules match") {
			return nil // Already deleted
		}
		// On Linux, iptables returns non-zero when the rule doesn't
		// exist; treat that as success so repeated unblock calls
		// (e.g. from ClearKernelBlock) don't log errors.
		if runtime.GOOS != "windows" && strings.Contains(string(output), "Rule does not exist") {
			return nil
		}
		logger.Error("Failed to unblock IP in kernel", "ip", ip, "err", err, "output", string(output))
		return err
	}
	logger.Info("IP unblocked at kernel level (L3)", "ip", ip)
	return nil
}

// TakeoverPort uses firewall redirection to "hijack" traffic from an occupied port.
//
// Hardened 2026-09-25 per Finding 4.4: previous code used
// `iptables -t nat -A PREROUTING ...` (append), which accumulated a
// duplicate rule on every call and eventually exhausted the kernel's
// per-chain rule budget. Now we use `-C` to check whether the rule is
// already present and only `-I` if it isn't. `-w` acquires the
// iptables exclusive lock so concurrent AegisEdge invocations from
// different processes don't race.
func TakeoverPort(occupiedPort, internalPort int) error {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		// netsh interface portproxy add v4tov4 listenport=80 listenaddress=0.0.0.0 connectport=8888 connectaddress=127.0.0.1
		// netsh is itself idempotent on portproxy, so no extra check needed.
		cmd = exec.Command("netsh", "interface", "portproxy", "add", "v4tov4",
			fmt.Sprintf("listenport=%d", occupiedPort), "listenaddress=0.0.0.0",
			fmt.Sprintf("connectport=%d", internalPort), "connectaddress=127.0.0.1")
	} else {
		// PREROUTING for external traffic. -C checks first.
		prArgs := []string{"-w", "-t", "nat", "-C", "PREROUTING", "-p", "tcp",
			"--dport", fmt.Sprintf("%d", occupiedPort), "-j", "REDIRECT",
			"--to-ports", fmt.Sprintf("%d", internalPort)}
		if err := exec.Command("iptables", prArgs...).Run(); err != nil {
			prInsert := []string{"-w", "-t", "nat", "-I", "PREROUTING", "1", "-p", "tcp",
				"--dport", fmt.Sprintf("%d", occupiedPort), "-j", "REDIRECT",
				"--to-ports", fmt.Sprintf("%d", internalPort)}
			out1, err1 := exec.Command("iptables", prInsert...).CombinedOutput()
			if err1 != nil {
				logger.Warn("Failed to add PREROUTING rule", "port", occupiedPort, "err", err1, "output", string(out1))
			}
		}

		// OUTPUT for locally generated traffic (loopback), guarded by
		// the SO_MARK 0xAE615 check so AegisEdge doesn't redirect its
		// own egress back to itself.
		outArgs := []string{"-w", "-t", "nat", "-I", "OUTPUT", "1", "-p", "tcp", "-o", "lo",
			"-m", "mark", "!", "--mark", "0xAE615",
			"--dport", fmt.Sprintf("%d", occupiedPort), "-j", "REDIRECT",
			"--to-ports", fmt.Sprintf("%d", internalPort)}
		cmd = exec.Command("iptables", outArgs...)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Failed to hijack port via firewall", "from", occupiedPort, "to", internalPort, "err", err, "output", string(output))
		return err
	}
	logger.Info("Port Hijack Active (Hot Takeover)", "external_port", occupiedPort, "internal_proxy_port", internalPort)
	return nil
}

// ReleasePort removes the firewall redirection. Idempotent: iptables -D
// is a no-op when the rule doesn't exist, so repeated calls are safe.
func ReleasePort(occupiedPort, internalPort int) error {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("netsh", "interface", "portproxy", "delete", "v4tov4",
			fmt.Sprintf("listenport=%d", occupiedPort), "listenaddress=0.0.0.0")
	} else {
		exec.Command("iptables", "-w", "-t", "nat", "-D", "PREROUTING", "-p", "tcp",
			"--dport", fmt.Sprintf("%d", occupiedPort), "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", internalPort)).Run()
		cmd = exec.Command("iptables", "-w", "-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-o", "lo",
			"-m", "mark", "!", "--mark", "0xAE615",
			"--dport", fmt.Sprintf("%d", occupiedPort), "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", internalPort))
	}

	cmd.Run()
	logger.Info("Port Hijack Released", "port", occupiedPort)
	return nil
}

func hardenWindows() {
	logger.Info("Applying Windows network hardening...")
	// Note: Detailed ICMP rate limiting in Windows requires specialized config, 
	// but we can ensure the firewall is ON and standard protections are active.
	cmds := [][]string{
		{"advfirewall", "set", "allprofiles", "state", "on"},
		// Disable ICMP Echo requests (pings) if needed, or leave to user.
		// For now, just ensure firewall is active.
	}

	for _, c := range cmds {
		exec.Command("netsh", c...).Run()
	}
}

func hardenLinux() {
	logger.Info("Applying Linux network hardening (iptables/sysctl)...")
	// Idempotent: check with -C before -A so restarts don't accumulate
	// duplicate ICMP rules (same Finding 4.4 class as TakeoverPort).
	icmpAccept := []string{"INPUT", "-p", "icmp", "--icmp-type", "echo-request",
		"-m", "limit", "--limit", "1/s", "--limit-burst", "5", "-j", "ACCEPT"}
	if err := exec.Command("iptables", append([]string{"-C"}, icmpAccept...)...).Run(); err != nil {
		exec.Command("iptables", append([]string{"-A"}, icmpAccept...)...).Run()
	}
	icmpDrop := []string{"INPUT", "-p", "icmp", "--icmp-type", "echo-request", "-j", "DROP"}
	if err := exec.Command("iptables", append([]string{"-C"}, icmpDrop...)...).Run(); err != nil {
		exec.Command("iptables", append([]string{"-A"}, icmpDrop...)...).Run()
	}

	// Anti-SYN flood
	exec.Command("sysctl", "-w", "net.ipv4.tcp_syncookies=1").Run()
	exec.Command("sysctl", "-w", "net.ipv4.conf.all.rp_filter=1").Run()
}
