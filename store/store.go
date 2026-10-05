package store

import "time"

// Storer is the common interface for all storage backends (Redis, In-Memory)
type Storer interface {
	Increment(key string, expiration time.Duration) (int64, error)
	// IncrementIfBelow atomically increments key and returns the new
	// value iff it would still be <= max. If the post-increment value
	// would exceed max, the counter is NOT modified and (max+1, nil)
	// is returned as a sentinel. Added 2026-09-25 per Finding 2.1 to
	// close the check-then-act race in L4 connection limiting.
	IncrementIfBelow(key string, max int64, expiration time.Duration) (int64, error)
	// AddClamped atomically applies delta to key and clamps the result
	// to [min, max]. Returns the final clamped value. Used by the
	// reputation manager to close the read-modify-write race (Finding 2.2).
	// On first write, the entry is given `expiration` TTL; subsequent
	// updates keep the original TTL (Redis PEXPIRE only on first INCR).
	AddClamped(key string, delta int64, minVal, maxVal int64, expiration time.Duration) (int64, error)
	Decrement(key string) (int64, error)
	GetCounter(key string) (int64, error)
	IsBlocked(key string) bool
	Block(key string, expiration time.Duration, blockType string)
	Unblock(key string) error
	ListBlocks() (map[string]string, error)
	Get(key string) (string, error)
	Set(key string, val string, expiration time.Duration) error
}
