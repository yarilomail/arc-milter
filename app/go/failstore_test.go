package main

import (
	"context"
	"errors"
	"net"
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
	return &dnsKeys{lookupTXT: failingDNS, grace: grace, now: ck.now, fails: &sharedFails{
		redis: &redisFails{rdb: rdb, prefix: "arc-milter:", ttl: grace + 24*time.Hour},
		local: newMemoryFails(grace),
	}}
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
