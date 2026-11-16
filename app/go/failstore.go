package main

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// failStore keeps when a key name first failed temporarily, shared by every
// replica and kept across restarts.
type failStore interface {
	// FirstFailure records a failure now and returns the first one.
	FirstFailure(ctx context.Context, name string, now time.Time) (time.Time, error)
	Clear(ctx context.Context, name string) error
}

// redisFails keeps the first failure as unix seconds at <prefix>dnsfail:<name>;
// the TTL, renewed on each failure, outlives the grace by a day, so a name
// still failing stays given up and one that went quiet is forgotten.
type redisFails struct {
	rdb    redis.UniversalClient
	prefix string
	ttl    time.Duration
}

func (r *redisFails) key(name string) string { return r.prefix + "dnsfail:" + name }

func (r *redisFails) FirstFailure(ctx context.Context, name string, now time.Time) (time.Time, error) {
	k := r.key(name)
	if _, err := r.rdb.SetNX(ctx, k, now.Unix(), r.ttl).Result(); err != nil {
		return time.Time{}, fmt.Errorf("failstore: set %s: %w", k, err)
	}
	v, err := r.rdb.Get(ctx, k).Result()
	if err != nil {
		return time.Time{}, fmt.Errorf("failstore: get %s: %w", k, err)
	}
	_ = r.rdb.Expire(ctx, k, r.ttl).Err()
	sec, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("failstore: %s holds %q", k, v)
	}
	return time.Unix(sec, 0), nil
}

func (r *redisFails) Clear(ctx context.Context, name string) error {
	if err := r.rdb.Del(ctx, r.key(name)).Err(); err != nil {
		return fmt.Errorf("failstore: del %s: %w", r.key(name), err)
	}
	return nil
}

// memoryFails stands in while Redis does not answer: mail is never held on
// Redis, and the count goes on in this process meanwhile.
type memoryFails struct {
	mu      sync.Mutex
	grace   time.Duration
	failing map[string]time.Time
}

func (m *memoryFails) FirstFailure(_ context.Context, name string, now time.Time) (time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if first, ok := m.failing[name]; ok {
		return first, nil
	}
	if len(m.failing) >= maxFailingNames {
		for n, t := range m.failing {
			if now.Sub(t) > m.grace {
				delete(m.failing, n)
			}
		}
		if len(m.failing) >= maxFailingNames {
			return now, nil
		}
	}
	m.failing[name] = now
	return now, nil
}

func (m *memoryFails) Clear(_ context.Context, name string) error {
	m.mu.Lock()
	delete(m.failing, name)
	m.mu.Unlock()
	return nil
}

// sharedFails is Redis with the process's memory behind it for the time
// Redis is down.
type sharedFails struct {
	redis failStore
	local *memoryFails
}

func (s *sharedFails) FirstFailure(ctx context.Context, name string, now time.Time) (time.Time, error) {
	first, err := s.redis.FirstFailure(ctx, name, now)
	if err != nil {
		redisErrors.Inc()
		slog.Warn("arc: Redis does not answer, the DNS failure is counted in this process", "name", name, "err", err)
		return s.local.FirstFailure(ctx, name, now)
	}
	return first, nil
}

func (s *sharedFails) Clear(ctx context.Context, name string) error {
	_ = s.local.Clear(ctx, name)
	if err := s.redis.Clear(ctx, name); err != nil {
		redisErrors.Inc()
		return err
	}
	return nil
}

func newMemoryFails(grace time.Duration) *memoryFails {
	return &memoryFails{grace: grace, failing: map[string]time.Time{}}
}

// newRedisClient is one address, or the master the Sentinels name.
func newRedisClient(c redisConfig) redis.UniversalClient {
	if len(c.sentinelAddrs) > 0 {
		return redis.NewFailoverClient(&redis.FailoverOptions{
			MasterName: c.sentinelMaster, SentinelAddrs: c.sentinelAddrs,
			SentinelUsername: c.sentinelUser, SentinelPassword: c.sentinelPassword,
			Username: c.user, Password: c.password, DB: c.db,
			DialTimeout: 2 * time.Second, ReadTimeout: time.Second, WriteTimeout: time.Second,
			ContextTimeoutEnabled: true,
		})
	}
	return redis.NewClient(&redis.Options{
		Addr: c.addr, Username: c.user, Password: c.password, DB: c.db,
		DialTimeout: 2 * time.Second, ReadTimeout: time.Second, WriteTimeout: time.Second,
		ContextTimeoutEnabled: true,
	})
}
