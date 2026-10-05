package store

import (
	"errors"
	"strconv"
	"sync"
	"time"
)

// localData holds a value with an optional expiry time.
type localData struct {
	value  string
	expiry time.Time // zero = no expiry
}

// localCounter holds a counter with an optional expiry time.
type localCounter struct {
	count  int64
	expiry time.Time
}

const numShards = 64

type localBlock struct {
	Type   string
	Expiry time.Time
}

type storeShard struct {
	counters map[string]localCounter
	blocks   map[string]localBlock
	data     map[string]localData
	mu       sync.RWMutex
}

type LocalStore struct {
	shards [numShards]*storeShard
	stop   chan struct{}
}

func NewLocalStore() *LocalStore {
	s := &LocalStore{
		stop: make(chan struct{}),
	}
	for i := 0; i < numShards; i++ {
		s.shards[i] = &storeShard{
			counters: make(map[string]localCounter),
			blocks:   make(map[string]localBlock),
			data:     make(map[string]localData),
		}
	}
	go s.cleanupLoop()
	return s
}

func (s *LocalStore) getShard(key string) *storeShard {
	hash := uint32(0)
	for i := 0; i < len(key); i++ {
		hash = 31*hash + uint32(key[i])
	}
	return s.shards[hash%numShards]
}

// Close stops the background cleanup goroutine.
func (s *LocalStore) Close() error {
	close(s.stop)
	return nil
}

func (s *LocalStore) Get(key string) (string, error) {
	shard := s.getShard(key)
	shard.mu.RLock()
	defer shard.mu.RUnlock()
	d := shard.data[key]
	if !d.expiry.IsZero() && time.Now().After(d.expiry) {
		return "", nil // expired
	}
	return d.value, nil
}

func (s *LocalStore) Set(key string, val string, expiration time.Duration) error {
	shard := s.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	expiry := time.Time{}
	if expiration > 0 {
		expiry = time.Now().Add(expiration)
	}
	shard.data[key] = localData{value: val, expiry: expiry}
	return nil
}

func (s *LocalStore) Increment(key string, expiration time.Duration) (int64, error) {
	shard := s.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	c := shard.counters[key]
	// Only set the expiry on the first increment for this key (new window).
	if c.count == 0 && expiration > 0 {
		c.expiry = time.Now().Add(expiration)
	}
	c.count++
	shard.counters[key] = c
	return c.count, nil
}

// IncrementIfBelow atomically increments key only if the post-increment
// value would still be <= max. Returns (newCount, nil) on success, or
// (max+1, nil) as a sentinel when the increment was refused.
//
// The whole read-modify-write happens under shard.mu, which closes the
// check-then-act race window that plain Increment + GetCounter exposed
// (Finding 2.1). Hardened 2026-09-25.
func (s *LocalStore) IncrementIfBelow(key string, max int64, expiration time.Duration) (int64, error) {
	shard := s.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	c := shard.counters[key]
	if c.count >= max {
		return max + 1, nil // sentinel: refused
	}
	c.count++
	if c.count == 1 && expiration > 0 {
		c.expiry = time.Now().Add(expiration)
	}
	shard.counters[key] = c
	return c.count, nil
}

// AddClamped atomically applies delta to key and clamps the result to
// [minVal, maxVal]. The whole read-modify-write happens under shard.mu
// so concurrent adjusts cannot lose updates (Finding 2.2). On first
// write (key absent), the entry is given `expiration` TTL; subsequent
// writes keep the original TTL so the window does not reset on every
// adjustment.
//
// Note: the TTL behaviour here intentionally differs from Increment
// — we use `data` (string-keyed) instead of `counters` so we can both
// store and clamp a signed value. Hardened 2026-09-25.
func (s *LocalStore) AddClamped(key string, delta int64, minVal, maxVal int64, expiration time.Duration) (int64, error) {
	if minVal > maxVal {
		return 0, errors.New("minVal must be <= maxVal")
	}
	shard := s.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	d, ok := shard.data[key]
	var cur int64
	if ok {
		if v, err := strconv.ParseInt(d.value, 10, 64); err == nil {
			cur = v
		}
	}
	next := cur + delta
	if next < minVal {
		next = minVal
	}
	if next > maxVal {
		next = maxVal
	}
	expiry := d.expiry
	if !ok && expiration > 0 {
		expiry = time.Now().Add(expiration)
	}
	shard.data[key] = localData{
		value:  strconv.FormatInt(next, 10),
		expiry: expiry,
	}
	return next, nil
}

func (s *LocalStore) Decrement(key string) (int64, error) {
	shard := s.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	c := shard.counters[key]
	if c.count > 0 { c.count-- }
	shard.counters[key] = c
	return c.count, nil
}

func (s *LocalStore) GetCounter(key string) (int64, error) {
	shard := s.getShard(key)
	shard.mu.RLock()
	defer shard.mu.RUnlock()
	return shard.counters[key].count, nil
}

func (s *LocalStore) IsBlocked(key string) bool {
	shard := s.getShard(key)
	shard.mu.RLock()
	defer shard.mu.RUnlock()
	
	block, ok := shard.blocks[key]
	if !ok {
		return false
	}
	
	if !block.Expiry.IsZero() && time.Now().After(block.Expiry) {
		return false
	}
	
	return true
}

func (s *LocalStore) Block(key string, expiration time.Duration, blockType string) {
	shard := s.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	
	expiry := time.Time{}
	if expiration > 0 {
		expiry = time.Now().Add(expiration)
	}
	
	shard.blocks[key] = localBlock{
		Type:   blockType,
		Expiry: expiry,
	}
}

func (s *LocalStore) Unblock(key string) error {
	shard := s.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	delete(shard.blocks, key)
	return nil
}

func (s *LocalStore) ListBlocks() (map[string]string, error) {
	res := make(map[string]string)
	for i := 0; i < numShards; i++ {
		shard := s.shards[i]
		shard.mu.RLock()
		for k, v := range shard.blocks {
			if v.Expiry.IsZero() || time.Now().Before(v.Expiry) {
				res[k] = v.Type
			}
		}
		shard.mu.RUnlock()
	}
	return res, nil
}

func (s *LocalStore) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			for i := 0; i < numShards; i++ {
				shard := s.shards[i]
				shard.mu.Lock()
				// Evict expired blocks
				for k, v := range shard.blocks {
					if !v.Expiry.IsZero() && now.After(v.Expiry) {
						delete(shard.blocks, k)
					}
				}
				// Evict expired counters
				for k, c := range shard.counters {
					if !c.expiry.IsZero() && now.After(c.expiry) {
						delete(shard.counters, k)
					}
				}
				// Evict expired data entries
				for k, d := range shard.data {
					if !d.expiry.IsZero() && now.After(d.expiry) {
						delete(shard.data, k)
					}
				}
				shard.mu.Unlock()
			}
		case <-s.stop:
			return
		}
	}
}
