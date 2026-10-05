package store

import (
	"context"
	"crypto/tls"
	"errors"
	"os"
	"runtime"
	"strings"
	"time"

	"aegisedge/logger"

	"github.com/redis/go-redis/v9"
)

// RedisStore wraps go-redis with a mandatory key prefix so the proxy's
// state (blocks, counters, reputation) never collides with other tenants
// on a shared Redis instance. Hardened 2026-09-25 per Finding 3.3.
type RedisStore struct {
	Client *redis.Client
	ctx    context.Context
	prefix string
}

// RedisConfig bundles all knobs.
type RedisConfig struct {
	Addr         string
	Password     string
	DB           int
	PoolSize     int
	MinIdleConns int
	KeyPrefix    string // namespace to avoid collisions on shared Redis
	UseTLS       bool   // AEGISEDGE_REDIS_TLS=1
}

// NewRedisStore constructs a Redis-backed store. Password is REQUIRED
// unless AEGISEDGE_REDIS_ALLOW_NO_AUTH=1 (dev only). Hardened 2026-09-25.
func NewRedisStore(addr string, password string) *RedisStore {
	cfg := RedisConfig{
		Addr:         addr,
		Password:     password,
		DB:           0,
		PoolSize:     10 * runtime.NumCPU(),
		MinIdleConns: 2,
		KeyPrefix:    "aegisedge:",
		UseTLS:       os.Getenv("AEGISEDGE_REDIS_TLS") == "1",
	}
	s, err := NewRedisStoreWithConfig(cfg)
	if err != nil {
		logger.Error("Redis store init failed", "err", err)
		return nil
	}
	return s
}

// NewRedisStoreWithConfig builds a Redis store from a RedisConfig.
// Returns an error when:
//   - password is empty and AEGISEDGE_REDIS_ALLOW_NO_AUTH != "1"
//   - the connection cannot be pinged within 5 seconds
func NewRedisStoreWithConfig(cfg RedisConfig) (*RedisStore, error) {
	if cfg.Password == "" && os.Getenv("AEGISEDGE_REDIS_ALLOW_NO_AUTH") != "1" {
		return nil, errors.New("redis password required (set AEGISEDGE_REDIS_PASSWORD or AEGISEDGE_REDIS_ALLOW_NO_AUTH=1 for dev)")
	}
	if cfg.PoolSize <= 0 {
		cfg.PoolSize = 10 * runtime.NumCPU()
	}
	if cfg.MinIdleConns < 0 {
		cfg.MinIdleConns = 0
	}
	if cfg.KeyPrefix == "" {
		cfg.KeyPrefix = "aegisedge:"
	}
	opts := &redis.Options{
		Addr:         cfg.Addr,
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConns,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	}
	if cfg.UseTLS {
		opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	client := redis.NewClient(opts)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, err
	}

	return &RedisStore{
		Client: client,
		ctx:    context.Background(),
		prefix: cfg.KeyPrefix,
	}, nil
}

func (s *RedisStore) Get(key string) (string, error) {
	val, err := s.Client.Get(s.ctx, s.prefix+key).Result()
	if err == redis.Nil {
		return "", nil
	}
	return val, err
}

func (s *RedisStore) Set(key string, val string, expiration time.Duration) error {
	return s.Client.Set(s.ctx, s.prefix+key, val, expiration).Err()
}

func (s *RedisStore) Increment(key string, expiration time.Duration) (int64, error) {
	script := `
		local val = redis.call("INCR", KEYS[1])
		if val == 1 then
			redis.call("PEXPIRE", KEYS[1], ARGV[1])
		end
		return val
	`
	val, err := s.Client.Eval(s.ctx, script, []string{s.prefix + key}, int(expiration.Milliseconds())).Int64()
	if err != nil {
		return 0, err
	}
	return val, nil
}

// IncrementIfBelow atomically increments key only if the post-increment
// value would still be <= max. Returns (max+1, nil) as a sentinel when
// the increment was refused. Hardened 2026-09-25 per Finding 2.1.
func (s *RedisStore) IncrementIfBelow(key string, max int64, expiration time.Duration) (int64, error) {
	script := `
		local cur = tonumber(redis.call("GET", KEYS[1]) or "0")
		if cur >= tonumber(ARGV[2]) then
			return tonumber(ARGV[2]) + 1
		end
		local val = redis.call("INCR", KEYS[1])
		if val == 1 then
			redis.call("PEXPIRE", KEYS[1], ARGV[1])
		end
		return val
	`
	val, err := s.Client.Eval(s.ctx, script, []string{s.prefix + key},
		int(expiration.Milliseconds()),
		max,
	).Int64()
	if err != nil {
		return 0, err
	}
	return val, nil
}

// AddClamped atomically applies delta to key and clamps to [minVal, maxVal].
// Hardened 2026-09-25 per Finding 2.2.
func (s *RedisStore) AddClamped(key string, delta int64, minVal, maxVal int64, expiration time.Duration) (int64, error) {
	if minVal > maxVal {
		return 0, errors.New("minVal must be <= maxVal")
	}
	script := `
		local cur = tonumber(redis.call("GET", KEYS[1]) or "0")
		local nxt = cur + tonumber(ARGV[1])
		if nxt < tonumber(ARGV[2]) then nxt = tonumber(ARGV[2]) end
		if nxt > tonumber(ARGV[3]) then nxt = tonumber(ARGV[3]) end
		local existed = redis.call("EXISTS", KEYS[1])
		redis.call("SET", KEYS[1], nxt)
		if existed == 0 then
			redis.call("PEXPIRE", KEYS[1], ARGV[4])
		end
		return nxt
	`
	val, err := s.Client.Eval(s.ctx, script, []string{s.prefix + key},
		delta,
		minVal,
		maxVal,
		int(expiration.Milliseconds()),
	).Int64()
	if err != nil {
		return 0, err
	}
	return val, nil
}

func (s *RedisStore) Decrement(key string) (int64, error) {
	return s.Client.Decr(s.ctx, s.prefix+key).Result()
}

func (s *RedisStore) GetCounter(key string) (int64, error) {
	val, err := s.Client.Get(s.ctx, s.prefix+key).Int64()
	if err == redis.Nil {
		return 0, nil
	}
	return val, err
}

func (s *RedisStore) IsBlocked(key string) bool {
	exists, err := s.Client.Exists(s.ctx, s.prefix+"block:"+key).Result()
	if err != nil {
		logger.Error("Redis check failed", "err", err)
		return false
	}
	return exists > 0
}

func (s *RedisStore) Block(key string, expiration time.Duration, blockType string) {
	s.Client.Set(s.ctx, s.prefix+"block:"+key, blockType, expiration)
	logger.Info("Distributed block issued", "key", key, "type", blockType, "duration", expiration)
}

func (s *RedisStore) Unblock(key string) error {
	return s.Client.Del(s.ctx, s.prefix+"block:"+key).Err()
}

func (s *RedisStore) ListBlocks() (map[string]string, error) {
	blocks := make(map[string]string)
	pattern := s.prefix + "block:*"
	var cursor uint64

	for {
		keys, nextCursor, err := s.Client.Scan(s.ctx, cursor, pattern, 100).Result()
		if err != nil {
			return nil, err
		}

		for _, k := range keys {
			val, _ := s.Client.Get(s.ctx, k).Result()
			ip := strings.TrimPrefix(k, s.prefix+"block:")
			blocks[ip] = val
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return blocks, nil
}
