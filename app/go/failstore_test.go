package main

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/redis/go-redis/v9"
)

// failingDNS is a resolver that answers SERVFAIL.
func failingDNS(context.Context, string) ([]string, error) {
	return nil, &net.DNSError{Err: "server misbehaving", IsTemporary: true}
}

func redisDNSKeys(mr *miniredis.Miniredis, ck *clock, grace time.Duration) *dnsKeys {
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	sf := newSharedFails(&redisFails{rdb: rdb, prefix: "arc-milter:", ttl: grace + 24*time.Hour}, newMemoryFails(grace))
	sf.now = ck.now
	return &dnsKeys{lookupTXT: failingDNS, grace: grace, now: ck.now, fails: sf}
}

// The first failure is kept in Redis under the prefix with a TTL: a new
// process (a restart, another replica) goes on counting from it instead of
// starting over, and a name nobody asks about is forgotten.
func TestDNSFailureCountSurvivesARestart(t *testing.T) {
	mr := miniredis.RunT(t)
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	first := redisDNSKeys(mr, ck, 4*time.Hour)
	if _, err := first.PublicKey(t.Context(), "s1", "a.example"); !errors.Is(err, errTempDNS) {
		t.Fatalf("first failure: %v", err)
	}
	const key = "arc-milter:dnsfail:s1._domainkey.a.example"
	if !mr.Exists(key) {
		t.Fatalf("no %s in Redis: %v", key, mr.Keys())
	}
	if ttl := mr.TTL(key); ttl != 28*time.Hour {
		t.Errorf("TTL %v, want the grace plus a day", ttl)
	}
	// Each failure renews the TTL, so a name still failing stays counted.
	mr.FastForward(20 * time.Hour)
	_, _ = first.PublicKey(t.Context(), "s1", "a.example")
	if ttl := mr.TTL(key); ttl != 28*time.Hour {
		t.Errorf("TTL after a later failure %v, want renewed to 28h", ttl)
	}
	ck.add(4 * time.Hour)
	restarted := redisDNSKeys(mr, ck, 4*time.Hour)
	if _, err := restarted.PublicKey(t.Context(), "s1", "a.example"); err == nil || errors.Is(err, errTempDNS) {
		t.Errorf("after a restart, past the grace: %v, want a permanent failure", err)
	}
	mr.FastForward(29 * time.Hour)
	if mr.Exists(key) {
		t.Error("the key outlived its TTL")
	}
}

// An answer from DNS clears the name in Redis.
func TestDNSAnswerClearsTheName(t *testing.T) {
	mr := miniredis.RunT(t)
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	d := redisDNSKeys(mr, ck, time.Hour)
	_, _ = d.PublicKey(t.Context(), "s1", "a.example")
	d.lookupTXT = func(context.Context, string) ([]string, error) {
		return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
	}
	_, _ = d.PublicKey(t.Context(), "s1", "a.example")
	d.fails.(*sharedFails).bg.Wait()
	if keys := mr.Keys(); len(keys) != 0 {
		t.Errorf("after an answer Redis still holds %v", keys)
	}
}

// With Redis down mail is not held on it: the count goes on in the process
// and the error is counted.
func TestRedisDownCountsInTheProcess(t *testing.T) {
	mr := miniredis.RunT(t)
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	d := redisDNSKeys(mr, ck, 4*time.Hour)
	mr.Close()
	before := testutil.ToFloat64(redisErrors)
	if _, err := d.PublicKey(t.Context(), "s1", "a.example"); !errors.Is(err, errTempDNS) {
		t.Fatalf("Redis down, first failure: %v, want errTempDNS", err)
	}
	ck.add(4 * time.Hour)
	if _, err := d.PublicKey(t.Context(), "s1", "a.example"); err == nil || errors.Is(err, errTempDNS) {
		t.Errorf("Redis down, past the grace: %v, want a permanent failure", err)
	}
	if testutil.ToFloat64(redisErrors) <= before {
		t.Error("Redis errors not counted")
	}
}

func TestLoadRedis(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  map[string]string
		ok   bool
	}{
		{"address", map[string]string{"REDIS_ADDR": "r:6379", "REDIS_KEY_PREFIX": "arc:"}, true},
		{"sentinels", map[string]string{"REDIS_SENTINEL_ADDRS": "a:26379, b:26379", "REDIS_SENTINEL_MASTER": "m", "REDIS_KEY_PREFIX": "arc:"}, true},
		{"no prefix", map[string]string{"REDIS_ADDR": "r:6379"}, false},
		{"neither", map[string]string{"REDIS_KEY_PREFIX": "arc:"}, false},
		{"both", map[string]string{"REDIS_ADDR": "r:6379", "REDIS_SENTINEL_ADDRS": "a:26379", "REDIS_SENTINEL_MASTER": "m", "REDIS_KEY_PREFIX": "arc:"}, false},
		{"sentinels without master", map[string]string{"REDIS_SENTINEL_ADDRS": "a:26379", "REDIS_KEY_PREFIX": "arc:"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range []string{"REDIS_ADDR", "REDIS_SENTINEL_ADDRS", "REDIS_SENTINEL_MASTER", "REDIS_KEY_PREFIX"} {
				t.Setenv(k, tc.set[k])
			}
			r, err := loadRedis()
			if (err == nil) != tc.ok {
				t.Fatalf("err %v, ok want %v", err, tc.ok)
			}
			if tc.name == "sentinels" && len(r.sentinelAddrs) != 2 {
				t.Errorf("sentinels %q", r.sentinelAddrs)
			}
		})
	}
}

// A lookup that ran into the message's deadline is still recorded: Redis is
// called on its own timeout, not on the message's spent context.
func TestDNSFailureAtTheDeadlineIsRecorded(t *testing.T) {
	mr := miniredis.RunT(t)
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	d := redisDNSKeys(mr, ck, time.Hour)
	d.lookupTXT = func(ctx context.Context, _ string) ([]string, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	before := testutil.ToFloat64(redisErrors)
	if _, err := d.PublicKey(ctx, "s1", "a.example"); !errors.Is(err, errTempDNS) {
		t.Fatalf("%v, want errTempDNS", err)
	}
	if !mr.Exists("arc-milter:dnsfail:s1._domainkey.a.example") {
		t.Error("a failure at the message's deadline did not reach Redis")
	}
	if testutil.ToFloat64(redisErrors) != before {
		t.Error("a healthy Redis counted as failing")
	}
}

// A healthy chain does not write to Redis on every lookup, and with Redis
// down a run of good lookups does not wait on it.
func TestGoodLookupsDoNotWaitOnRedis(t *testing.T) {
	mr := miniredis.RunT(t)
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	d := redisDNSKeys(mr, ck, time.Hour)
	k := rsaKey(t)
	m := &mapKeys{records: map[string]string{}}
	m.add(t, "s1._domainkey.a.example", k)
	rec := m.records["s1._domainkey.a.example"]
	d.lookupTXT = func(context.Context, string) ([]string, error) { return []string{rec}, nil }
	sf := d.fails.(*sharedFails)
	// The first good lookup deletes once (and the client says hello).
	if _, err := d.PublicKey(t.Context(), "s1", "a.example"); err != nil {
		t.Fatal(err)
	}
	sf.bg.Wait()
	before := mr.CommandCount()
	for i := 0; i < 50; i++ {
		if _, err := d.PublicKey(t.Context(), "s1", "a.example"); err != nil {
			t.Fatal(err)
		}
	}
	sf.bg.Wait()
	if n := mr.CommandCount() - before; n != 0 {
		t.Errorf("50 more good lookups sent Redis %d commands, want none", n)
	}
	mr.Close()
	ck.add(clearEvery)
	start := time.Now()
	for i := 0; i < 50; i++ {
		_, _ = d.PublicKey(t.Context(), "s1", "b"+strconv.Itoa(i)+".example")
	}
	if el := time.Since(start); el > 200*time.Millisecond {
		t.Errorf("50 good lookups with Redis down took %v", el)
	}
	sf.bg.Wait()
}

// A Redis that takes connections and never answers costs a run of failing
// lookups one Redis timeout, not one each: Redis is left alone for a while.
func TestSilentRedisIsLeftAlone(t *testing.T) {
	ln, err := new(net.ListenConfig).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	rdb := redis.NewClient(&redis.Options{Addr: ln.Addr().String(), DialTimeout: time.Second, ReadTimeout: 5 * time.Second, ContextTimeoutEnabled: true})
	sf := newSharedFails(&redisFails{rdb: rdb, prefix: "arc-milter:", ttl: 28 * time.Hour}, newMemoryFails(time.Hour))
	sf.now = ck.now
	d := &dnsKeys{lookupTXT: failingDNS, grace: time.Hour, now: ck.now, fails: sf}
	start := time.Now()
	for i := 0; i < 10; i++ {
		if _, err := d.PublicKey(t.Context(), "s1", "a.example"); !errors.Is(err, errTempDNS) {
			t.Fatalf("lookup %d: %v", i, err)
		}
	}
	if el := time.Since(start); el > redisTimeout+500*time.Millisecond {
		t.Errorf("10 failing lookups with a silent Redis took %v", el)
	}
}
