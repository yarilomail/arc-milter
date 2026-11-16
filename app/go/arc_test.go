// rsa1024min=0 lets a test make and verify a 512-bit key, so the milter's
// own size check is what refuses it.
//
//go:debug rsa1024min=0
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0kaba0hub/go-milter"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// The fixtures in testdata were sealed by dkimpy (testdata/gen_dkimpy.py),
// an implementation independent of this one.

// parseMessage splits a message into its fields, values with the space
// after the colon, and its body.
func parseMessage(t *testing.T, msg []byte) ([]field, []byte) {
	t.Helper()
	head, body, ok := bytes.Cut(msg, []byte("\r\n\r\n"))
	if !ok {
		t.Fatal("no end of headers")
	}
	var fields []field
	for _, line := range strings.Split(string(head), "\r\n") {
		if line != "" && (line[0] == ' ' || line[0] == '\t') {
			fields[len(fields)-1].value += "\r\n" + line
			continue
		}
		name, value, found := strings.Cut(line, ":")
		if !found {
			t.Fatalf("not a field: %q", line)
		}
		fields = append(fields, field{name, value})
	}
	return fields, body
}

func render(fields []field, body []byte) []byte {
	var b bytes.Buffer
	for _, f := range fields {
		b.WriteString(f.raw() + "\r\n")
	}
	b.WriteString("\r\n")
	b.Write(body)
	return b.Bytes()
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// mapKeys answers key lookups from a table; delay and temp stand for a slow
// and a failing resolver.
type mapKeys struct {
	mu      sync.Mutex
	records map[string]string
	temp    bool
	delay   time.Duration
	lookups int
}

func fixtureKeys(t *testing.T) *mapKeys {
	t.Helper()
	m := &mapKeys{records: map[string]string{}}
	sc := bufio.NewScanner(bytes.NewReader(fixture(t, "keys.txt")))
	for sc.Scan() {
		name, rec, _ := strings.Cut(sc.Text(), " ")
		m.records[strings.TrimSuffix(name, ".")] = rec
	}
	return m
}

func (m *mapKeys) add(t *testing.T, name string, k *rsa.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.records[name] = "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)
	m.mu.Unlock()
}

func (m *mapKeys) count() int { m.mu.Lock(); defer m.mu.Unlock(); return m.lookups }

func (m *mapKeys) PublicKey(ctx context.Context, selector, domain string) (*rsa.PublicKey, error) {
	m.mu.Lock()
	m.lookups++
	rec, ok := m.records[selector+"._domainkey."+domain]
	temp, delay := m.temp, m.delay
	m.mu.Unlock()
	d := &dnsKeys{grace: time.Hour, now: time.Now, failing: map[string]time.Time{}, lookupTXT: func(ctx context.Context, _ string) ([]string, error) {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if temp {
			return nil, &net.DNSError{Err: "server misbehaving", IsTemporary: true}
		}
		if !ok {
			return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
		}
		return []string{rec}, nil
	}}
	return d.PublicKey(ctx, selector, domain)
}

// bodyHashes hashes a body for whatever canonicalization asks.
func bodyHashes(body []byte) func(bool, int64) []byte {
	return func(relaxed bool, limit int64) []byte {
		h := newBodyHasher(relaxed, limit)
		_, _ = h.Write(body)
		return h.Sum()
	}
}

func validateMessage(t *testing.T, msg []byte, keys keyResolver) (string, string) {
	t.Helper()
	fields, body := parseMessage(t, msg)
	cv, why, err := collect(fields).validate(t.Context(), fields, bodyHashes(body), keys)
	if err != nil {
		t.Fatal(err)
	}
	return cv, why
}

// Canonical bodies, RFC 6376 3.4.3 and 3.4.4: trailing empty lines go, an
// empty simple body is one CRLF, an empty relaxed one nothing, and a last
// line without CRLF gets one.
func TestBodyCanonicalization(t *testing.T) {
	for _, tc := range []struct {
		name, in      string
		relaxed       bool
		limit         int64
		want          string
		inTwoPiecesAt int
	}{
		{"simple empty", "", false, -1, "\r\n", 0},
		{"relaxed empty", "", true, -1, "", 0},
		{"simple only empty lines", "\r\n\r\n", false, -1, "\r\n", 0},
		{"relaxed only empty lines", "\r\n\r\n", true, -1, "", 0},
		{"simple keeps spaces", " a  b \r\n\r\n\r\n", false, -1, " a  b \r\n", 0},
		{"relaxed squeezes spaces", " a \t b \r\nc\r\n\r\n", true, -1, " a b\r\nc\r\n", 0},
		{"inner empty lines stay", "a\r\n\r\n\r\nb\r\n", true, -1, "a\r\n\r\n\r\nb\r\n", 0},
		{"no final CRLF", "a\r\nb", false, -1, "a\r\nb\r\n", 0},
		{"relaxed line of spaces is empty", "a\r\n  \r\n", true, -1, "a\r\n", 0},
		{"l= cuts the canonical body", "abcdef\r\n", false, 3, "abc", 0},
		{"chunk boundary inside CRLF", "a \r\n\r\nb\r\n", true, -1, "a\r\n\r\nb\r\n", 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newBodyHasher(tc.relaxed, tc.limit)
			if tc.inTwoPiecesAt > 0 {
				_, _ = h.Write([]byte(tc.in[:tc.inTwoPiecesAt]))
				_, _ = h.Write([]byte(tc.in[tc.inTwoPiecesAt:]))
			} else {
				_, _ = h.Write([]byte(tc.in))
			}
			want := sha256.Sum256([]byte(tc.want))
			if got := h.Sum(); !bytes.Equal(got, want[:]) {
				t.Errorf("hash of %q is not that of %q", tc.in, tc.want)
			}
		})
	}
}

func TestRelaxedHeader(t *testing.T) {
	got := relaxedHeader(field{"SubJect ", " a \t b\r\n\t c  "})
	if got != "subject:a b c\r\n" {
		t.Errorf("relaxed %q", got)
	}
}

// Chains dkimpy sealed validate here as dkimpy validates them; a body or a
// signed field changed after the seal breaks them.
func TestValidateChainsSealedByAnotherImplementation(t *testing.T) {
	keys := fixtureKeys(t)
	for _, tc := range []struct {
		name, file, from, to string
		want                 string
	}{
		{"one hop", "one-hop.eml", "", "", cvPass},
		{"two hops", "two-hops.eml", "", "", cvPass},
		{"body changed", "two-hops.eml", "line one", "line ONE", cvFail},
		{"signed field changed", "two-hops.eml", "Subject: arc fixture", "Subject: arc fixturE", cvFail},
		{"newest seal changed", "two-hops.eml", "i=2; cv=pass;", "i=2; cv=pass; ", cvPass},
		{"newest seal says fail", "cv-fail.eml", "", "", cvFail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := fixture(t, tc.file)
			if tc.from != "" {
				if !bytes.Contains(msg, []byte(tc.from)) {
					t.Fatalf("%q not in the fixture", tc.from)
				}
				msg = bytes.Replace(msg, []byte(tc.from), []byte(tc.to), 1)
			}
			if cv, why := validateMessage(t, msg, keys); cv != tc.want {
				t.Errorf("cv=%s (%s), want %s", cv, why, tc.want)
			}
		})
	}
}

// Sets that are not 1..n, each once and complete, fail before any key is
// looked up (RFC 8617 5.2 step 2).
func TestBrokenStructureFails(t *testing.T) {
	keys := fixtureKeys(t)
	fields, body := parseMessage(t, fixture(t, "two-hops.eml"))
	drop := func(name string, i int) []field {
		var out []field
		for _, f := range fields {
			if strings.EqualFold(f.name, name) && strings.Contains(relaxedValue(f.value), fmt.Sprintf("i=%d;", i)) {
				continue
			}
			out = append(out, f)
		}
		return out
	}
	dup := append([]field{}, fields...)
	for _, f := range fields {
		if f.name == hdrAMS && strings.Contains(f.value, "i=1;") {
			dup = append(dup, f)
		}
	}
	for _, tc := range []struct {
		name   string
		fields []field
	}{
		{"AAR of set 1 missing", drop(hdrAAR, 1)},
		{"set 1 missing", drop(hdrAS, 1)[:0:0]},
		{"AMS i=1 twice", dup},
		{"instance 51", append([]field{{hdrAS, " i=51; cv=pass; a=rsa-sha256; d=x; s=y; b=z"}}, fields...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := tc.fields
			if tc.name == "set 1 missing" {
				for _, f := range fields {
					if !strings.HasPrefix(f.name, "ARC-") || !strings.Contains(f.value, "i=1") {
						fs = append(fs, f)
					}
				}
			}
			before := keys.count()
			cv, why, err := collect(fs).validate(t.Context(), fs, bodyHashes(body), keys)
			if err != nil || cv != cvFail {
				t.Errorf("cv=%s (%s) %v, want fail", cv, why, err)
			}
			if keys.count() != before {
				t.Errorf("a broken structure looked up %d keys", keys.count()-before)
			}
		})
	}
}

// sealOn seals a message as this milter would and returns it with the new
// set on top.
func sealOn(t *testing.T, msg []byte, k sealKey, keys keyResolver, authserv string) ([]byte, string) {
	t.Helper()
	fields, body := parseMessage(t, msg)
	c := collect(fields)
	cv, _, err := c.validate(t.Context(), fields, bodyHashes(body), keys)
	if err != nil {
		t.Fatal(err)
	}
	s := &session{fields: fields, authservID: authserv}
	aar, ams, as, err := seal(k, c, fields, bodyHashes(body)(true, -1), c.n+1, cv, authserv, s.authResults(), time.Unix(1794787300, 0))
	if err != nil {
		t.Fatal(err)
	}
	top := []field{{hdrAS, as}, {hdrAMS, ams}, {hdrAAR, aar}}
	return render(append(top, fields...), body), cv
}

func ourKey(t *testing.T, keys *mapKeys) sealKey {
	t.Helper()
	k := sealKey{domain: "fwd.example", selector: "arc", signer: rsaKey(t)}
	keys.add(t, "arc._domainkey.fwd.example", k.signer)
	return k
}

// A seal on a passing chain says cv=pass and the chain with it validates,
// here and, run by hand, with dkimpy (ARC_DKIMPY_OUT keeps the message).
func TestSealExtendsAChain(t *testing.T) {
	keys := fixtureKeys(t)
	k := ourKey(t, keys)
	msg := append([]byte("Authentication-Results: mx.fwd.example; spf=pass smtp.mailfrom=alice@example.org; arc=pass\r\n"),
		fixture(t, "two-hops.eml")...)
	sealed, cv := sealOn(t, msg, k, keys, "mx.fwd.example")
	if cv != cvPass || !bytes.HasPrefix(sealed, []byte("ARC-Seal: i=3; a=rsa-sha256; t=1794787300; cv=pass; d=fwd.example;")) {
		t.Fatalf("cv=%s, message starts %q", cv, sealed[:60])
	}
	if got, why := validateMessage(t, sealed, keys); got != cvPass {
		t.Errorf("the chain with our seal: cv=%s (%s)", got, why)
	}
	if !bytes.Contains(sealed, []byte("ARC-Authentication-Results: i=3; mx.fwd.example; spf=pass smtp.mailfrom=alice@example.org; arc=pass\r\n")) {
		t.Errorf("the AAR is not a copy of this ADMD's Authentication-Results:\n%s", sealed)
	}
	if dir := os.Getenv("ARC_DKIMPY_OUT"); dir != "" {
		_ = os.WriteFile(dir+"/sealed-by-arc-milter.eml", sealed, 0o600)
		_ = os.WriteFile(dir+"/arc-key.txt", []byte("arc._domainkey.fwd.example. "+keys.records["arc._domainkey.fwd.example"]+"\n"), 0o600)
	}
	// A first seal: no chain before it.
	first, cv := sealOn(t, fixture(t, "two-hops.eml")[bytes.Index(fixture(t, "two-hops.eml"), []byte("From: ")):], k, keys, "mx.fwd.example")
	if cv != cvNone {
		t.Errorf("a message without a chain: cv=%s", cv)
	}
	if got, why := validateMessage(t, first, keys); got != cvPass {
		t.Errorf("a first seal: cv=%s (%s)", got, why)
	}
}

// RFC 8617 5.1.2: a chain this hop finds broken is sealed cv=fail, and that
// seal signs only its own set, as if it were the only one.
func TestBrokenChainIsSealedOverItsOwnSet(t *testing.T) {
	keys := fixtureKeys(t)
	k := ourKey(t, keys)
	msg := bytes.Replace(fixture(t, "two-hops.eml"), []byte("line one"), []byte("line ONE"), 1)
	sealed, cv := sealOn(t, msg, k, keys, "mx.fwd.example")
	if cv != cvFail {
		t.Fatalf("cv=%s, want fail", cv)
	}
	fields, _ := parseMessage(t, sealed)
	c := collect(fields)
	if c.n != 3 || c.lastCV() != cvFail {
		t.Fatalf("instance %d, cv %s", c.n, c.lastCV())
	}
	if why, err := verifyRSA(t.Context(), keys, c.sets[3].asTags, sealInput(c.sets, 3, 3)); why != "" || err != nil {
		t.Errorf("the seal does not verify over its own set: %s %v", why, err)
	}
	if why, _ := verifyRSA(t.Context(), keys, c.sets[3].asTags, sealInput(c.sets, 1, 3)); why == "" {
		t.Error("the cv=fail seal also verifies over the whole chain")
	}
}

// A key lookup that may answer later is never a fail: it is an error the
// session turns into tempfail. A name that does not exist is a fail.
func TestTemporaryDNSIsNotAFail(t *testing.T) {
	keys := fixtureKeys(t)
	keys.temp = true
	fields, body := parseMessage(t, fixture(t, "two-hops.eml"))
	cv, why, err := collect(fields).validate(t.Context(), fields, bodyHashes(body), keys)
	if !errors.Is(err, errTempDNS) {
		t.Errorf("SERVFAIL: cv=%s (%s) err=%v, want errTempDNS", cv, why, err)
	}
	keys.temp = false
	delete(keys.records, "s1._domainkey.a.example")
	if cv, _, err := collect(fields).validate(t.Context(), fields, bodyHashes(body), keys); err != nil || cv != cvFail {
		t.Errorf("NXDOMAIN: cv=%s err=%v, want fail", cv, err)
	}
	// A revoked key (empty p=) is permanent too.
	keys.records["s1._domainkey.a.example"] = "v=DKIM1; k=rsa; p="
	if cv, _, err := collect(fields).validate(t.Context(), fields, bodyHashes(body), keys); err != nil || cv != cvFail {
		t.Errorf("revoked key: cv=%s err=%v, want fail", cv, err)
	}
}

func TestParsePublicKeyRecord(t *testing.T) {
	k := rsaKey(t)
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	p := base64.StdEncoding.EncodeToString(der)
	for _, tc := range []struct {
		rec string
		ok  bool
	}{
		{"v=DKIM1; k=rsa; p=" + p, true},
		{"p=" + p[:40] + " " + p[40:], true},
		{"v=DKIM1; k=ed25519; p=" + p, false},
		{"v=DKIM1; p=", false},
		{"v=DKIM1; p=!!", false},
	} {
		if _, err := parsePublicKey(tc.rec); (err == nil) != tc.ok {
			t.Errorf("%.40q: err %v, ok want %v", tc.rec, err, tc.ok)
		}
	}
}

// A name that keeps failing temporarily tempfails while its first failure
// is recent and counts as failed past the grace; any answer starts over.
func TestDNSGraceForANameThatKeepsFailing(t *testing.T) {
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	answer := false
	d := &dnsKeys{grace: 4 * time.Hour, now: ck.now, failing: map[string]time.Time{},
		lookupTXT: func(context.Context, string) ([]string, error) {
			if answer {
				return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
			}
			return nil, &net.DNSError{Err: "server misbehaving", IsTemporary: true}
		}}
	try := func() error { _, err := d.PublicKey(t.Context(), "s1", "a.example"); return err }
	if err := try(); !errors.Is(err, errTempDNS) {
		t.Fatalf("first failure: %v, want errTempDNS", err)
	}
	ck.add(3*time.Hour + 59*time.Minute)
	if err := try(); !errors.Is(err, errTempDNS) {
		t.Errorf("inside the grace: %v, want errTempDNS", err)
	}
	ck.add(time.Minute)
	if err := try(); err == nil || errors.Is(err, errTempDNS) {
		t.Errorf("past the grace: %v, want a permanent failure", err)
	}
	answer = true
	_ = try()
	answer = false
	if err := try(); !errors.Is(err, errTempDNS) {
		t.Errorf("after an answer the name starts over: %v, want errTempDNS", err)
	}
}

// amsSimpleChain is one ARC set whose AMS uses simple header
// canonicalization, signed over the fields as written in raw.
func amsSimpleChain(t *testing.T, k sealKey, raw string) string {
	t.Helper()
	fields, body := parseMessage(t, []byte(raw))
	names := []string{"From", "Subject"}
	pairs := [][2]string{{"i", "1"}, {"a", "rsa-sha256"}, {"c", "simple/simple"}, {"d", k.domain}, {"s", k.selector},
		{"h", "From:Subject"}, {"bh", base64.StdEncoding.EncodeToString(bodyHashes(body)(false, -1))}, {"b", ""}}
	ams := foldTags(len(hdrAMS), pairs)
	b, err := signRSA(k, selectHeaders(fields, names, false)+strings.TrimSuffix(simpleHeader(field{hdrAMS, ams}), "\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	ams += foldBase64(b)
	aar := " i=1; mx.a.example; none"
	as := foldTags(len(hdrAS), [][2]string{{"i", "1"}, {"a", "rsa-sha256"}, {"cv", cvNone}, {"d", k.domain}, {"s", k.selector}, {"b", ""}})
	sets := map[int]*arcSet{1: {aar: field{hdrAAR, aar}, ams: field{hdrAMS, ams}, as: field{hdrAS, as}}}
	if b, err = signRSA(k, sealInput(sets, 1, 1)); err != nil {
		t.Fatal(err)
	}
	return hdrAS + ":" + as + foldBase64(b) + "\r\n" + hdrAMS + ":" + ams + "\r\n" + hdrAAR + ":" + aar + "\r\n" + raw
}

// An earlier hop's AMS with simple header canonicalization checks only on
// the bytes it signed. The milter cannot rebuild a field that had no space,
// or two, after its colon: such a message is left unsealed, never sealed
// cv=fail; one written with the usual space seals as pass.
func TestSimpleHeaderAMSThatCannotBeRebuilt(t *testing.T) {
	keys := fixtureKeys(t)
	hop := sealKey{domain: "simple.example", selector: "s", signer: rsaKey(t)}
	keys.add(t, "s._domainkey.simple.example", hop.signer)
	c, _ := sealCache(t, keys)
	addr := startMilter(t, c, keys, 5*time.Second)
	for _, tc := range []struct {
		name, subject string
		sealed        bool
	}{
		{"one space", "Subject: hello\r\n", true},
		{"two spaces", "Subject:  hello\r\n", false},
		{"no space", "Subject:hello\r\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := amsSimpleChain(t, hop, "From: a@example.org\r\n"+tc.subject+"\r\nbody\r\n")
			before := testutil.ToFloat64(sealResults.WithLabelValues("simple_unverifiable"))
			r := send(t, addr, []byte(msg))
			if (len(r.inserted) == 3) != tc.sealed || r.eom == nil || r.eom.Code != milter.ActAccept {
				t.Fatalf("eom %+v, %d inserted; sealed want %v", r.eom, len(r.inserted), tc.sealed)
			}
			if tc.sealed {
				if !strings.Contains(relaxedValue(r.inserted[2].HeaderValue), "cv=pass;") {
					t.Errorf("seal %q, want cv=pass", r.inserted[2].HeaderValue)
				}
				return
			}
			if testutil.ToFloat64(sealResults.WithLabelValues("simple_unverifiable")) != before+1 {
				t.Error("simple_unverifiable not counted")
			}
		})
	}
}

// RFC 8301: a key under 1024 bits makes its signature fail, so a chain with
// one is never vouched for with cv=pass; nor does this milter seal with one.
func TestSmallKeysFail(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatal(err)
	}
	keys := fixtureKeys(t)
	k := sealKey{domain: "small.example", selector: "s", signer: small}
	keys.add(t, "s._domainkey.small.example", small)
	sealed, _ := sealOn(t, []byte("From: a@example.org\r\nSubject: s\r\n\r\nbody\r\n"), k, keys, authserv)
	if cv, why := validateMessage(t, sealed, keys); cv != cvFail || !strings.Contains(why, "under 1024") {
		t.Errorf("a 512-bit seal: cv=%s (%s), want fail for its size", cv, why)
	}
	der := x509.MarshalPKCS1PrivateKey(small)
	if _, err := parsePrivateKey(der); err == nil {
		t.Error("a 512-bit private key was taken for sealing")
	}
}

// The new set takes the number after the highest i= of any ARC field, read
// past a broken one, so it never repeats a number already there; at 50 there
// is no new set.
func TestNewInstanceIsAboveEveryNumberThere(t *testing.T) {
	keys := fixtureKeys(t)
	c, _ := sealCache(t, keys)
	addr := startMilter(t, c, keys, 5*time.Second)
	for _, tc := range []struct {
		name, extra string
		want        string // the new instance; empty for no seal
	}{
		{"a broken field names 4", "ARC-Message-Signature: i=4; broken\r\n", "i=5;"},
		{"a broken field names 50", "ARC-Seal: i=50; broken\r\n", ""},
		{"a broken field names 51", "ARC-Seal: i=51; cv=pass\r\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := send(t, addr, append([]byte(tc.extra), fixture(t, "one-hop.eml")...))
			if tc.want == "" {
				if r.eoh.Code != milter.ActAccept || len(r.inserted) != 0 {
					t.Errorf("eoh %+v, %d inserted; want no seal", r.eoh, len(r.inserted))
				}
				return
			}
			if len(r.inserted) != 3 {
				t.Fatalf("%d inserted", len(r.inserted))
			}
			for _, m := range r.inserted {
				if !strings.HasPrefix(relaxedValue(m.HeaderValue), tc.want) {
					t.Errorf("%s %q, want %s", m.HeaderName, m.HeaderValue, tc.want)
				}
			}
			if !strings.Contains(relaxedValue(r.inserted[2].HeaderValue), "cv=fail;") {
				t.Errorf("seal over a broken chain %q, want cv=fail", r.inserted[2].HeaderValue)
			}
		})
	}
}
