package main

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/0kaba0hub/go-milter"
)

const authserv = "mx.fwd.example"

// milterRun is one message through a real milter conversation.
type milterRun struct {
	eoh, eom *milter.Action
	inserted []milter.ModifyAction
	elapsed  time.Duration
}

func startMilter(t *testing.T, keys *keyCache, dns keyResolver, dnsTimeout time.Duration) string {
	t.Helper()
	ln, err := new(net.ListenConfig).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config{sealDomain: "fwd.example", authservID: authserv, dnsTimeout: dnsTimeout, milterRead: 5 * time.Second, milterWrite: 5 * time.Second}
	srv := newMilterServer(cfg, keys, dns)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

// send passes msg as Postfix does over milter protocol 2: each value without
// the space after its colon, folds as LF.
func send(t *testing.T, addr string, msg []byte) milterRun {
	t.Helper()
	cl := milter.NewClientWithOptions("tcp", addr, milter.ClientOptions{
		ActionMask:   milter.OptAddHeader,
		ProtocolMask: milter.OptNoConnect | milter.OptNoHelo | milter.OptNoRcptTo,
		ReadTimeout:  10 * time.Second, WriteTimeout: 10 * time.Second,
	})
	t.Cleanup(func() { _ = cl.Close() })
	sess, err := cl.Session()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sess.Close() }()
	if _, err := sess.Mail("<alice@example.org>", nil); err != nil {
		t.Fatal(err)
	}
	fields, body := parseMessage(t, msg)
	for _, f := range fields {
		if _, err := sess.HeaderField(f.name, strings.TrimLeft(strings.ReplaceAll(f.value, "\r\n", "\n"), " ")); err != nil {
			t.Fatal(err)
		}
	}
	var r milterRun
	if r.eoh, err = sess.HeaderEnd(); err != nil {
		t.Fatal(err)
	}
	if r.eoh.Code != milter.ActContinue {
		return r
	}
	start := time.Now()
	mods, act, err := sess.BodyReadFrom(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.elapsed, r.eom = time.Since(start), act
	for _, m := range mods {
		if m.Code == milter.ActInsertHeader {
			r.inserted = append(r.inserted, m)
		}
	}
	return r
}

// withInserted is msg with the inserted fields applied, as the MTA would.
func withInserted(t *testing.T, msg []byte, ins []milter.ModifyAction) []byte {
	t.Helper()
	fields, body := parseMessage(t, msg)
	for _, m := range ins {
		v := " " + strings.ReplaceAll(m.HeaderValue, "\n", "\r\n")
		fields = append(fields[:m.HeaderIndex], append([]field{{m.HeaderName, v}}, fields[m.HeaderIndex:]...)...)
	}
	return render(fields, body)
}

func sealCache(t *testing.T, keys *mapKeys) (*keyCache, *table) {
	t.Helper()
	k := ourKey(t, keys)
	tb := &table{rows: map[string]row{"fwd.example": {"fwd.example", "arc", pkcs8PEM(t, k.signer)}}}
	c, _ := newTestCache(tb, plainKeys{}, 10)
	return c, tb
}

const ownAR = "Authentication-Results: " + authserv + "; spf=pass smtp.mailfrom=alice@example.org; arc=pass\r\n"

// Through the protocol: the three fields go on top, AS first, and the
// message with them validates; the AAR copies this ADMD's results only.
func TestMilterSealsThroughTheProtocol(t *testing.T) {
	keys := fixtureKeys(t)
	c, _ := sealCache(t, keys)
	addr := startMilter(t, c, keys, 5*time.Second)
	foreign := "Authentication-Results: mx.other.example; dkim=pass\r\n"
	for _, tc := range []struct {
		name, msg, aar string
		cv             string
	}{
		{"on a chain", foreign + ownAR + string(fixture(t, "two-hops.eml")),
			"i=3; " + authserv + "; spf=pass smtp.mailfrom=alice@example.org; arc=pass", cvPass},
		{"without this ADMD's results", foreign + string(fixture(t, "one-hop.eml")), "i=2; " + authserv + "; none", cvPass},
		{"first seal", ownAR + "From: a@example.org\r\nSubject: s\r\n\r\nbody\r\n",
			"i=1; " + authserv + "; spf=pass smtp.mailfrom=alice@example.org; arc=pass", cvNone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := send(t, addr, []byte(tc.msg))
			if r.eom == nil || r.eom.Code != milter.ActAccept || len(r.inserted) != 3 {
				t.Fatalf("eoh %+v eom %+v, %d fields inserted", r.eoh, r.eom, len(r.inserted))
			}
			order := []string{hdrAAR, hdrAMS, hdrAS}
			for i, m := range r.inserted {
				if m.HeaderName != order[i] || m.HeaderIndex != 0 {
					t.Errorf("insert %d: %s at %d, want %s at 0", i, m.HeaderName, m.HeaderIndex, order[i])
				}
				if strings.HasPrefix(m.HeaderValue, " ") {
					t.Errorf("%s starts with a space, and the MTA adds one", m.HeaderName)
				}
			}
			if got := relaxedValue(r.inserted[0].HeaderValue); got != tc.aar {
				t.Errorf("AAR %q, want %q", got, tc.aar)
			}
			out := withInserted(t, []byte(tc.msg), r.inserted)
			if !strings.Contains(relaxedValue(r.inserted[2].HeaderValue), "cv="+tc.cv+";") {
				t.Errorf("seal %q, want cv=%s", r.inserted[2].HeaderValue, tc.cv)
			}
			if cv, why := validateMessage(t, out, keys); cv != cvPass {
				t.Errorf("the sealed message: cv=%s (%s)", cv, why)
			}
		})
	}
}

// RFC 8617 5.1 step 2: after a seal that says cv=fail nothing is added,
// and the MTA is told so at the end of the headers.
func TestMilterStopsAfterAFailedSeal(t *testing.T) {
	keys := fixtureKeys(t)
	c, tb := sealCache(t, keys)
	r := send(t, startMilter(t, c, keys, 5*time.Second), fixture(t, "cv-fail.eml"))
	if r.eoh.Code != milter.ActAccept || len(r.inserted) != 0 {
		t.Errorf("eoh %+v, %d inserted; want accept and nothing", r.eoh, len(r.inserted))
	}
	if tb.count() != 0 || keys.count() != 0 {
		t.Errorf("%d key queries, %d DNS lookups for a chain that ended", tb.count(), keys.count())
	}
}

// fiftySets is a header block at instance 50; its seals are never checked.
func fiftySets() string {
	var b strings.Builder
	for i := maxInstance; i >= 1; i-- {
		cv := cvPass
		if i == 1 {
			cv = cvNone
		}
		fmt.Fprintf(&b, "ARC-Seal: i=%d; a=rsa-sha256; cv=%s; d=x.example; s=s; b=AA==\r\n", i, cv)
		fmt.Fprintf(&b, "ARC-Message-Signature: i=%d; a=rsa-sha256; d=x.example; s=s; h=from; bh=AA==; b=AA==\r\n", i)
		fmt.Fprintf(&b, "ARC-Authentication-Results: i=%d; mx.x.example; none\r\n", i)
	}
	return b.String() + "From: a@example.org\r\n\r\nbody\r\n"
}

// Instance 50 is the last (RFC 8617 4.2.1): no 51st set.
func TestMilterStopsAtTheLastInstance(t *testing.T) {
	keys := fixtureKeys(t)
	c, _ := sealCache(t, keys)
	r := send(t, startMilter(t, c, keys, 5*time.Second), []byte(fiftySets()))
	if r.eoh.Code != milter.ActAccept || len(r.inserted) != 0 {
		t.Errorf("eoh %+v, %d inserted; want accept and nothing", r.eoh, len(r.inserted))
	}
}

// The key, as decided for dkim-milter: a key once read seals on while the
// database or Vault is down; one never read tempfails; no row for the
// selector is configuration, and the message goes on unsealed.
func TestMilterKeyStates(t *testing.T) {
	keys := fixtureKeys(t)
	msg := []byte(ownAR + string(fixture(t, "two-hops.eml")))
	for _, tc := range []struct {
		name    string
		warm    bool // the key was read before the failure
		row     bool
		down    bool
		eohWant milter.ActionCode
		sealed  bool
	}{
		{"cached, store down", true, true, true, milter.ActContinue, true},
		{"never read, store down", false, true, true, milter.ActTempFail, false},
		{"no row, store up", false, false, false, milter.ActAccept, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, tb := sealCache(t, keys)
			if !tc.row {
				tb.rows = map[string]row{}
			}
			if tc.warm {
				if _, ok, err := c.lookup(t.Context(), "fwd.example"); !ok || err != nil {
					t.Fatal(ok, err)
				}
			}
			tb.mu.Lock()
			tb.fail = tc.down
			tb.mu.Unlock()
			r := send(t, startMilter(t, c, keys, 5*time.Second), msg)
			if r.eoh.Code != tc.eohWant {
				t.Fatalf("end of headers %c, want %c", r.eoh.Code, tc.eohWant)
			}
			if (len(r.inserted) == 3) != tc.sealed {
				t.Errorf("%d fields inserted, sealed want %v", len(r.inserted), tc.sealed)
			}
		})
	}
}

// A lookup that may answer later tempfails the message, never seals it
// cv=fail; and all lookups of a message share one deadline, so three slow
// ones cannot hold it three times as long.
func TestMilterTempfailsOnTemporaryDNS(t *testing.T) {
	msg := []byte(ownAR + string(fixture(t, "two-hops.eml")))
	t.Run("SERVFAIL", func(t *testing.T) {
		keys := fixtureKeys(t)
		c, _ := sealCache(t, keys)
		keys.temp = true
		r := send(t, startMilter(t, c, keys, 5*time.Second), msg)
		if r.eom == nil || r.eom.Code != milter.ActTempFail || len(r.inserted) != 0 {
			t.Errorf("eom %+v, %d inserted; want tempfail and nothing", r.eom, len(r.inserted))
		}
	})
	t.Run("one deadline", func(t *testing.T) {
		keys := fixtureKeys(t)
		c, _ := sealCache(t, keys)
		// Three lookups of 200 ms each fit a per-lookup 300 ms, not one 300 ms in all.
		keys.delay = 200 * time.Millisecond
		r := send(t, startMilter(t, c, keys, 300*time.Millisecond), msg)
		if r.eom == nil || r.eom.Code != milter.ActTempFail {
			t.Errorf("eom %+v after %v, want tempfail", r.eom, r.elapsed)
		}
		if r.elapsed > 550*time.Millisecond {
			t.Errorf("the message waited %v on DNS, past its 300 ms", r.elapsed)
		}
	})
}

// Session state does not reach the next message on the same connection.
func TestNothingCarriesOverToTheNextMessage(t *testing.T) {
	s := &session{fields: []field{{"From", " a"}}, sealing: true, ours: newBodyHasher(true, -1), chain: chain{n: 3}}
	if _, err := s.MailFrom("", &milter.Modifier{}); err != nil {
		t.Fatal(err)
	}
	if s.fields != nil || s.sealing || s.ours != nil || s.chain.n != 0 {
		t.Errorf("state after MAIL FROM: %+v", s)
	}
}
