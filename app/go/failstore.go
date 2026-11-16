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

const (
	// redisTimeout bounds one Redis call. It is not the message's deadline:
	// a lookup that ran into that deadline must still be recorded.
	redisTimeout = 300 * time.Millisecond
	// redisPause is how long Redis is left alone after it failed, so a
	// Redis outage costs a message at most one redisTimeout.
	redisPause = 30 * time.Second
	// clearEvery is the least time between two deletes of one name, so a
	// healthy chain does not write to Redis on every lookup.
	clearEvery = 5 * time.Minute
)

// sharedFails is Redis with the process's memory behind it for the time
// Redis is down. Deletes go in the background and at most once per name per
// clearEvery; a failure of the name lets the next one through.
type sharedFails struct {
	redis failStore
	local *memoryFails
	now   func() time.Time

	mu         sync.Mutex
	pauseUntil time.Time
	cleared    map[string]time.Time
	bg         sync.WaitGroup
}

func newSharedFails(r failStore, local *memoryFails) *sharedFails {
	return &sharedFails{redis: r, local: local, now: time.Now, cleared: map[string]time.Time{}}
}

func (s *sharedFails) paused() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.now().Before(s.pauseUntil)
}

func (s *sharedFails) failed(err error) {
	redisErrors.Inc()
	slog.Warn("arc: Redis does not answer, DNS failures are counted in this process for a while", "pause", redisPause.String(), "err", err)
	s.mu.Lock()
	s.pauseUntil = s.now().Add(redisPause)
	s.mu.Unlock()
}

func (s *sharedFails) FirstFailure(_ context.Context, name string, now time.Time) (time.Time, error) {
	s.mu.Lock()
	delete(s.cleared, name)
	s.mu.Unlock()
	if s.paused() {
		return s.local.FirstFailure(context.Background(), name, now)
	}
	ctx, cancel := context.WithTimeout(context.Background(), redisTimeout)
	defer cancel()
	first, err := s.redis.FirstFailure(ctx, name, now)
	if err != nil {
		s.failed(err)
		return s.local.FirstFailure(ctx, name, now)
	}
	return first, nil
}

func (s *sharedFails) Clear(_ context.Context, name string) error {
	_ = s.local.Clear(context.Background(), name)
	s.mu.Lock()
	now := s.now()
	if last, ok := s.cleared[name]; ok && now.Sub(last) < clearEvery {
		s.mu.Unlock()
		return nil
	}
	if len(s.cleared) >= maxFailingNames {
		for n, t := range s.cleared {
			if now.Sub(t) >= clearEvery {
				delete(s.cleared, n)
			}
		}
		if len(s.cleared) >= maxFailingNames {
			s.mu.Unlock()
			return nil
		}
	}
	s.cleared[name] = now
	s.mu.Unlock()
	if s.paused() {
		return nil
	}
	s.bg.Add(1)
	go func() {
		defer s.bg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), redisTimeout)
		defer cancel()
		if err := s.redis.Clear(ctx, name); err != nil {
			s.failed(err)
		}
	}()
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
