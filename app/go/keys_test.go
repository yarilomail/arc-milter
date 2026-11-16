package main

// The key cache and Vault client are dkim-milter's, copied; so are these
// tests, with RSA keys, the only kind ARC seals with.

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pkcs8PEM(t *testing.T, k crypto.Signer) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

type countingDecryptor struct {
	calls, items atomic.Int32
	fail         atomic.Bool
	nilFor       string
	delay        time.Duration
}

func (d *countingDecryptor) Decrypt(_ context.Context, stored []string) ([][]byte, error) {
	d.calls.Add(1)
	d.items.Add(int32(len(stored)))
	time.Sleep(d.delay)
	if d.fail.Load() {
		return nil, errors.New("sealed")
	}
	out := make([][]byte, len(stored))
	for i, s := range stored {
		if s != d.nilFor {
			out[i] = []byte(s)
		}
	}
	return out, nil
}

type table struct {
	mu      sync.Mutex
	rows    map[string]row
	queries int
	fail    bool
	// gate, when set before the cache is used, holds every query until it closes.
	gate chan struct{}
}

func (tb *table) fetch(_ context.Context, domain string) (row, bool, error) {
	if tb.gate != nil {
		<-tb.gate
	}
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.queries++
	if tb.fail {
		return row{}, false, errors.New("database down")
	}
	r, ok := tb.rows[domain]
	return r, ok, nil
}

func (tb *table) set(d string, r row) { tb.mu.Lock(); tb.rows[d] = r; tb.mu.Unlock() }

func (tb *table) count() int { tb.mu.Lock(); defer tb.mu.Unlock(); return tb.queries }

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }

func newTestCache(tb *table, dec decryptor, size int) (*keyCache, *clock) {
	c := newKeyCache(tb.fetch, dec, size, 10*time.Minute, time.Minute)
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	c.now = ck.now
	return c, ck
}

func TestKeyCacheMissThenHit(t *testing.T) {
	tb := &table{rows: map[string]row{"a.example": {"a.example", "s1", pkcs8PEM(t, rsaKey(t))}}}
	dec := &countingDecryptor{}
	c, _ := newTestCache(tb, dec, 10)
	for i := 0; i < 3; i++ {
		k, ok, err := c.lookup(t.Context(), "A.Example")
		if err != nil || !ok || k.selector != "s1" {
			t.Fatalf("lookup %d: %+v %v %v", i, k, ok, err)
		}
	}
	if tb.count() != 1 || dec.calls.Load() != 1 {
		t.Errorf("three lookups: %d queries, %d decrypts; want 1 and 1", tb.count(), dec.calls.Load())
	}
}

func TestKeyCacheSingleflight(t *testing.T) {
	tb := &table{rows: map[string]row{"a.example": {"a.example", "s1", pkcs8PEM(t, rsaKey(t))}}}
	dec := &countingDecryptor{delay: 50 * time.Millisecond}
	c, _ := newTestCache(tb, dec, 10)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok, err := c.lookup(t.Context(), "a.example"); err != nil || !ok {
				t.Errorf("lookup: %v %v", ok, err)
			}
		}()
	}
	wg.Wait()
	if tb.count() != 1 || dec.calls.Load() != 1 {
		t.Errorf("50 concurrent misses: %d queries, %d decrypts; want 1 and 1", tb.count(), dec.calls.Load())
	}
}

func TestKeyCacheTTLAndRotation(t *testing.T) {
	k1 := pkcs8PEM(t, rsaKey(t))
	tb := &table{rows: map[string]row{"a.example": {"a.example", "s1", k1}}}
	dec := &countingDecryptor{}
	c, ck := newTestCache(tb, dec, 10)
	_, _, _ = c.lookup(t.Context(), "a.example")
	ck.add(11 * time.Minute)
	if k, _, _ := c.lookup(t.Context(), "a.example"); k.selector != "s1" {
		t.Errorf("past the TTL: selector %q, want the cached s1", k.selector)
	}
	c.bg.Wait()
	if tb.count() != 2 || dec.calls.Load() != 1 {
		t.Errorf("unchanged row after TTL: %d queries, %d decrypts; want 2, 1", tb.count(), dec.calls.Load())
	}
	tb.set("a.example", row{"a.example", "s2", pkcs8PEM(t, rsaKey(t))})
	if k, _, _ := c.lookup(t.Context(), "a.example"); k.selector != "s1" {
		t.Errorf("rotation visible before the TTL: %q", k.selector)
	}
	ck.add(11 * time.Minute)
	if k, _, _ := c.lookup(t.Context(), "a.example"); k.selector != "s1" {
		t.Errorf("the lookup that starts the refresh: %q, want s1 served meanwhile", k.selector)
	}
	c.bg.Wait()
	if k, _, _ := c.lookup(t.Context(), "a.example"); k.selector != "s2" || dec.calls.Load() != 2 {
		t.Errorf("after the refresh: selector %q, %d decrypts; want s2, 2", k.selector, dec.calls.Load())
	}
}

func TestKeyCacheStaleDoesNotWaitOnTheDatabase(t *testing.T) {
	tb := &table{rows: map[string]row{"a.example": {"a.example", "s1", pkcs8PEM(t, rsaKey(t))}}}
	c, ck := newTestCache(tb, &countingDecryptor{}, 10)
	_, _, _ = c.lookup(t.Context(), "a.example")
	ck.add(11 * time.Minute)
	tb.gate = make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 20; i++ {
			if k, ok, err := c.lookup(t.Context(), "a.example"); err != nil || !ok || k.selector != "s1" {
				t.Errorf("lookup %d: %+v %v %v", i, k, ok, err)
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("lookups of an expired key waited on the database")
	}
	close(tb.gate)
	c.bg.Wait()
	if tb.count() != 2 {
		t.Errorf("20 lookups past the TTL: %d queries in all, want 2 (the first load and one refresh)", tb.count())
	}
}

func TestKeyCacheNegative(t *testing.T) {
	tb := &table{rows: map[string]row{}}
	c, ck := newTestCache(tb, &countingDecryptor{}, 10)
	for i := 0; i < 3; i++ {
		if _, ok, err := c.lookup(t.Context(), "none.example"); ok || err != nil {
			t.Fatalf("lookup %d: %v %v", i, ok, err)
		}
	}
	if tb.count() != 1 {
		t.Errorf("three lookups of a keyless domain: %d queries, want 1", tb.count())
	}
	tb.set("none.example", row{"none.example", "s1", pkcs8PEM(t, rsaKey(t))})
	ck.add(61 * time.Second)
	_, _, _ = c.lookup(t.Context(), "none.example")
	c.bg.Wait()
	if _, ok, _ := c.lookup(t.Context(), "none.example"); !ok {
		t.Error("a row added after the miss TTL is not seen")
	}
}

func TestKeyCacheFailedRefreshOfAnEvictedEntry(t *testing.T) {
	tb := &table{rows: map[string]row{
		"a.example": {"a.example", "s1", pkcs8PEM(t, rsaKey(t))},
		"b.example": {"b.example", "s1", pkcs8PEM(t, rsaKey(t))},
	}}
	dec := &countingDecryptor{}
	c, ck := newTestCache(tb, dec, 1)
	_, _, _ = c.lookup(t.Context(), "a.example")
	ck.add(11 * time.Minute)
	dec.fail.Store(true)
	tb.set("a.example", row{"a.example", "s2", pkcs8PEM(t, rsaKey(t))}) // the refresh must decrypt, and fails
	tb.gate = make(chan struct{})
	_, _, _ = c.lookup(t.Context(), "a.example") // starts the refresh, held at the query
	c.mu.Lock()
	c.drop(c.entries["a.example"]) // evicted while the refresh runs
	c.mu.Unlock()
	close(tb.gate)
	c.bg.Wait()
	tb.mu.Lock()
	tb.fail = true
	tb.mu.Unlock()
	if k, ok, err := c.lookup(t.Context(), "a.example"); err != nil || !ok || k.selector != "s1" {
		t.Errorf("after a failed refresh of an evicted entry: %+v %v %v, want the cached s1", k, ok, err)
	}
	if c.withKey != 1 || len(c.entries) != 1 {
		t.Errorf("%d keys counted, %d entries; want 1 and 1", c.withKey, len(c.entries))
	}
}

func TestKeyCacheUnavailable(t *testing.T) {
	tb := &table{rows: map[string]row{
		"cached.example": {"cached.example", "s1", pkcs8PEM(t, rsaKey(t))},
		"new.example":    {"new.example", "s1", pkcs8PEM(t, rsaKey(t))},
	}}
	dec := &countingDecryptor{}
	c, ck := newTestCache(tb, dec, 10)
	_, _, _ = c.lookup(t.Context(), "cached.example")
	_, _, _ = c.lookup(t.Context(), "keyless.example")
	for _, failure := range []string{"vault", "db"} {
		t.Run(failure, func(t *testing.T) {
			dec.fail.Store(failure == "vault")
			tb.mu.Lock()
			tb.fail = failure == "db"
			tb.mu.Unlock()
			if _, _, err := c.lookup(t.Context(), "new.example"); !errors.Is(err, errUnavailable) {
				t.Errorf("new domain: %v, want errUnavailable", err)
			}
			ck.add(11 * time.Minute)
			if k, ok, err := c.lookup(t.Context(), "cached.example"); err != nil || !ok || k.selector != "s1" {
				t.Errorf("cached domain past its TTL: %+v %v %v, want the cached key", k, ok, err)
			}
			if _, ok, err := c.lookup(t.Context(), "keyless.example"); err != nil || ok {
				t.Errorf("keyless domain past its miss TTL: %v %v, want keyless, not unavailable", ok, err)
			}
			c.bg.Wait()
			ck.add(11 * time.Minute)
			if k, ok, err := c.lookup(t.Context(), "cached.example"); err != nil || !ok || k.selector != "s1" {
				t.Errorf("cached domain after a failed refresh: %+v %v %v, want the cached key", k, ok, err)
			}
			c.bg.Wait()
		})
	}
}

func TestKeyCacheEviction(t *testing.T) {
	tb := &table{rows: map[string]row{}}
	for _, d := range []string{"a", "b", "c"} {
		tb.rows[d+".example"] = row{d + ".example", "s1", pkcs8PEM(t, rsaKey(t))}
	}
	c, _ := newTestCache(tb, &countingDecryptor{}, 2)
	_, _, _ = c.lookup(t.Context(), "a.example")
	_, _, _ = c.lookup(t.Context(), "b.example")
	_, _, _ = c.lookup(t.Context(), "a.example")
	_, _, _ = c.lookup(t.Context(), "c.example")
	before := tb.count()
	_, _, _ = c.lookup(t.Context(), "a.example")
	if tb.count() != before {
		t.Error("a, used last, was evicted")
	}
	_, _, _ = c.lookup(t.Context(), "b.example")
	if tb.count() != before+1 {
		t.Error("b, least recently used, was kept beyond the size")
	}
	if len(c.entries) != 2 || c.lru.Len() != 2 {
		t.Errorf("%d entries, %d in the list; want 2", len(c.entries), c.lru.Len())
	}
}

func TestVaultTransit(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("sa-jwt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		switch r.URL.Path {
		case "/v1/auth/kubernetes/login":
			if in["role"] != "dkim" || in["jwt"] != "sa-jwt" {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
				return
			}
			_, _ = w.Write([]byte(`{"auth":{"client_token":"tok"}}`))
		case "/v1/transit/decrypt/dkim":
			if r.Header.Get("X-Vault-Token") != "tok" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			var res []map[string]string
			for _, it := range in["batch_input"].([]any) {
				ct := it.(map[string]any)["ciphertext"].(string)
				if ct == "vault:v1:bad" {
					res = append(res, map[string]string{"error": "cipher: message authentication failed"})
					continue
				}
				res = append(res, map[string]string{"plaintext": base64.StdEncoding.EncodeToString([]byte("pem-of-" + ct))})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"batch_results": res}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	cfg := vaultConfig{addr: srv.URL, authPath: "kubernetes", role: "dkim", tokenFile: tokenFile, transitPath: "transit", transitKey: "dkim"}

	v, err := newVaultTransit(cfg)
	if err != nil {
		t.Fatal(err)
	}
	out, err := v.Decrypt(t.Context(), []string{"vault:v1:a", "vault:v1:bad", " vault:v1:b\n"})
	if err != nil {
		t.Fatal(err)
	}
	if string(out[0]) != "pem-of-vault:v1:a" || out[1] != nil || string(out[2]) != "pem-of-vault:v1:b" {
		t.Errorf("results %q", out)
	}

	cfg.role = "other"
	v, _ = newVaultTransit(cfg)
	if _, err := v.Decrypt(t.Context(), []string{"vault:v1:a"}); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("a refused login gave %v", err)
	}
}

func TestVaultTokenReuse(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("sa-jwt"), 0o600); err != nil {
		t.Fatal(err)
	}
	var logins, decrypts atomic.Int32
	var revoked atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/kubernetes/login":
			n := logins.Add(1)
			_, _ = fmt.Fprintf(w, `{"auth":{"client_token":"tok%d","lease_duration":600}}`, n)
		case "/v1/transit/decrypt/dkim":
			decrypts.Add(1)
			if revoked.Load() && r.Header.Get("X-Vault-Token") == "tok1" {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":{"batch_results":[{"plaintext":"cGVt"}]}}`))
		}
	}))
	t.Cleanup(srv.Close)
	v, err := newVaultTransit(vaultConfig{addr: srv.URL, authPath: "kubernetes", role: "dkim", tokenFile: tokenFile, transitPath: "transit", transitKey: "dkim"})
	if err != nil {
		t.Fatal(err)
	}
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	v.now = ck.now
	for i := 0; i < 3; i++ {
		if _, err := v.Decrypt(t.Context(), []string{"vault:v1:x"}); err != nil {
			t.Fatal(err)
		}
	}
	if logins.Load() != 1 {
		t.Errorf("three decrypts within the TTL: %d logins, want 1", logins.Load())
	}
	revoked.Store(true)
	if _, err := v.Decrypt(t.Context(), []string{"vault:v1:x"}); err != nil {
		t.Fatalf("after a 403: %v", err)
	}
	if logins.Load() != 2 {
		t.Errorf("a 403: %d logins, want 2 (one fresh login, then the retry)", logins.Load())
	}
	ck.add(9 * time.Minute)
	if _, err := v.Decrypt(t.Context(), []string{"vault:v1:x"}); err != nil {
		t.Fatal(err)
	}
	if logins.Load() != 3 {
		t.Errorf("past four fifths of the TTL: %d logins, want 3", logins.Load())
	}
}

func TestVaultTokenWithoutTTL(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("sa-jwt"), 0o600); err != nil {
		t.Fatal(err)
	}
	var logins atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/kubernetes/login":
			logins.Add(1)
			_, _ = w.Write([]byte(`{"auth":{"client_token":"tok","lease_duration":0}}`))
		case "/v1/transit/decrypt/dkim":
			_, _ = w.Write([]byte(`{"data":{"batch_results":[{"plaintext":"cGVt"}]}}`))
		}
	}))
	t.Cleanup(srv.Close)
	v, err := newVaultTransit(vaultConfig{addr: srv.URL, authPath: "kubernetes", role: "dkim", tokenFile: tokenFile, transitPath: "transit", transitKey: "dkim"})
	if err != nil {
		t.Fatal(err)
	}
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	v.now = ck.now
	for i := 0; i < 3; i++ {
		if _, err := v.Decrypt(t.Context(), []string{"vault:v1:x"}); err != nil {
			t.Fatal(err)
		}
		ck.add(24 * time.Hour)
	}
	if logins.Load() != 1 {
		t.Errorf("three decrypts a day apart with lease 0: %d logins, want 1", logins.Load())
	}
}

func TestVaultCheckNeedsDecrypt(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("sa-jwt"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, answer string
		code         int
		ok           bool
	}{
		{"update", `{"capabilities":["update"],"transit/decrypt/dkim":["update"]}`, 200, true},
		{"root", `{"capabilities":["root"],"transit/decrypt/dkim":["root"]}`, 200, true},
		{"read only", `{"capabilities":["read"],"transit/decrypt/dkim":["read"]}`, 200, false},
		{"deny", `{"capabilities":["deny"],"transit/decrypt/dkim":["deny"]}`, 200, false},
		{"other path only", `{"capabilities":["update"],"transit/decrypt/other":["update"]}`, 200, false},
		{"refused", `{"errors":["permission denied"]}`, 403, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/auth/kubernetes/login":
					_, _ = w.Write([]byte(`{"auth":{"client_token":"tok","lease_duration":600}}`))
				case "/v1/sys/capabilities-self":
					var in struct{ Paths []string }
					if err := json.NewDecoder(r.Body).Decode(&in); err != nil || len(in.Paths) != 1 || in.Paths[0] != "transit/decrypt/dkim" {
						t.Errorf("capabilities asked for %v (%v), want transit/decrypt/dkim", in.Paths, err)
					}
					w.WriteHeader(tc.code)
					_, _ = w.Write([]byte(tc.answer))
				}
			}))
			defer srv.Close()
			v, err := newVaultTransit(vaultConfig{addr: srv.URL, authPath: "kubernetes", role: "dkim", tokenFile: tokenFile, transitPath: "transit", transitKey: "dkim"})
			if err != nil {
				t.Fatal(err)
			}
			if err := v.Check(t.Context()); (err == nil) != tc.ok {
				t.Errorf("Check: %v, want ok = %v", err, tc.ok)
			}
		})
	}
}

func TestWaitReadyRunsTheKeyQuery(t *testing.T) {
	var asked atomic.Value
	var fail atomic.Bool
	fail.Store(true)
	fetch := func(_ context.Context, domain string) (row, bool, error) {
		asked.Store(domain)
		if fail.Load() {
			return row{}, false, errors.New("Table 'yarilo.dkim' doesn't exist")
		}
		return row{}, false, nil
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var ready atomic.Bool
	done := make(chan struct{})
	go func() { waitReady(ctx, fetch, plainKeys{}, &ready); close(done) }()
	time.Sleep(200 * time.Millisecond)
	if ready.Load() {
		t.Fatal("ready while the key query fails")
	}
	fail.Store(false)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("not ready after the key query answered")
	}
	if !ready.Load() || asked.Load() != readyProbeDomain {
		t.Errorf("ready %v after asking for %v", ready.Load(), asked.Load())
	}
}
