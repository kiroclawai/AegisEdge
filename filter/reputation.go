package filter

import (
	"fmt"
	"strconv"
	"sync"
	"time"

	"aegisedge/logger"
	"aegisedge/notifier"
	"aegisedge/store"
)

const (
	TrustKeyPrefix = "trust:"
	TrustMax       = 10
	TrustMin       = -10
	TrustReward    = 1
	TrustPenalty   = -2
)

// kernelBlockedSet deduplicates BlockIPKernel invocations so that two
// concurrent reputation penalties for the same IP do not enqueue two
// iptables calls (Finding 2.2). Entries are removed when the IP is
// unblocked so a later attack can re-trigger the kernel rule after
// manual remediation.
var kernelBlockedSet sync.Map

// ReputationManager tracks client trust scores in the persistent store.
type ReputationManager struct {
	store store.Storer
}

func NewReputationManager(s store.Storer) *ReputationManager {
	return &ReputationManager{store: s}
}

// GetTrust returns the current trust score for an IP. Default is 0.
func (m *ReputationManager) GetTrust(ip string) int {
	key := TrustKeyPrefix + ip
	score, err := m.store.Get(key)
	if err != nil || score == "" {
		return 0
	}
	val, err := strconv.Atoi(score)
	if err != nil {
		return 0
	}
	return val
}

// Reward increases trust when a client behaves well (e.g., solves a challenge).
func (m *ReputationManager) Reward(ip string) {
	m.adjust(ip, TrustReward)
}

// Penalize decreases trust when a client behaves poorly (e.g., hits rate limits).
func (m *ReputationManager) Penalize(ip string) {
	m.adjust(ip, TrustPenalty)
}

// adjust applies delta atomically via AddClamped, then evaluates
// thresholds. The previous GetTrust+Set read-modify-write allowed
// concurrent adjusts to lose updates and duplicate kernel blocks
// (Finding 2.2). Hardened 2026-09-25.
func (m *ReputationManager) adjust(ip string, delta int) {
	key := TrustKeyPrefix + ip
	newScore, err := m.store.AddClamped(key, int64(delta),
		int64(TrustMin), int64(TrustMax), 24*time.Hour)
	if err != nil {
		logger.Error("reputation adjust failed", "ip", ip, "delta", delta, "err", err)
		return
	}

	// Warning: trust is persistently low but not yet terminal.
	if newScore <= int64(TrustMin)/2 && newScore > int64(TrustMin) {
		logger.Warn("Low reputation IP detected", "ip", ip, "score", newScore)
		notifier.SendAlert(fmt.Sprintf("Warning: Persistent low reputation for %s (Score: %d)", ip, newScore), "WARNING")
	}

	// Terminal reputation: kernel-level drop. Idempotent — only one
	// concurrent caller per IP wins the load-and-store check.
	if newScore <= int64(TrustMin) {
		m.blockIPKernelOnce(ip)
		notifier.SendAlert(fmt.Sprintf("Kernel-level block issued for %s (Terminal reputation)", ip), "CRITICAL")
	}
}

// blockIPKernelOnce invokes BlockIPKernel at most once per IP until
// ClearKernelBlock is called. Replaces the unguarded BlockIPKernel
// call that could fire twice under concurrent penalties (Finding 2.2).
func (m *ReputationManager) blockIPKernelOnce(ip string) {
	if _, loaded := kernelBlockedSet.LoadOrStore(ip, struct{}{}); loaded {
		return // already blocked at kernel level
	}
	if err := BlockIPKernel(ip); err != nil {
		logger.Error("Kernel block failed, falling back to application-layer block", "ip", ip, "err", err)
		kernelBlockedSet.Delete(ip) // allow a retry on the next penalty
	}
}

// ClearKernelBlock removes an IP from the kernel-block dedupe set so a
// future penalty can re-trigger the kernel rule. Should be called from
// the manual unblock path so a remediation cycle works end-to-end.
func ClearKernelBlock(ip string) {
	kernelBlockedSet.Delete(ip)
}

// GetMultiplier returns a rate limit multiplier based on trust.
// Trust 10 = 2.0x throughput
// Trust 0  = 1.0x throughput
// Trust -10 = 0.5x throughput
func (m *ReputationManager) GetMultiplier(ip string) float64 {
	trust := m.GetTrust(ip)
	if trust >= 0 {
		return 1.0 + (float64(trust) / 10.0)
	}
	// Scale -1 to -10 linearly to 0.9 to 0.5
	return 1.0 + (float64(trust) * 0.05)
}
