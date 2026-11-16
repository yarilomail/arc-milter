package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/textproto"
	"strings"
	"time"

	"github.com/0kaba0hub/go-milter"
)

// lookupTimeout bounds one key lookup: a database query and a Vault decrypt.
const lookupTimeout = 10 * time.Second

// session seals one message as it streams: the headers are kept, the body
// only goes through the hashers.
type session struct {
	keys       *keyCache
	dns        keyResolver
	sealDomain string
	authservID string
	// dnsTimeout is one deadline for every key lookup of a message.
	dnsTimeout time.Duration
	now        func() time.Time

	fields  []field
	queueID string

	chain chain
	key   key
	// ours hashes the body for the new AMS, relaxed; theirs for the newest
	// AMS the message came with, in that one's canonicalization.
	ours, theirs *bodyHasher
	sealing      bool
}

func (s *session) reset() {
	s.fields, s.queueID = nil, ""
	s.chain, s.key = chain{}, key{}
	s.ours, s.theirs, s.sealing = nil, nil, false
}

func (s *session) Connect(string, string, uint16, net.IP, *milter.Modifier) (milter.Response, error) {
	return milter.RespContinue, nil
}

func (s *session) Helo(string, *milter.Modifier) (milter.Response, error) {
	return milter.RespContinue, nil
}

func (s *session) MailFrom(string, *milter.Modifier) (milter.Response, error) {
	s.reset()
	return milter.RespContinue, nil
}

func (s *session) RcptTo(string, *milter.Modifier) (milter.Response, error) {
	return milter.RespContinue, nil
}

// Header keeps the field as it came. The milter protocol this library speaks
// (version 2) has Postfix drop the space after the colon; it is put back,
// the usual one, so a simple-canonicalized AMS checks on the original bytes.
func (s *session) Header(name, value string, _ *milter.Modifier) (milter.Response, error) {
	v := strings.ReplaceAll(value, "\r\n", "\n")
	v = strings.ReplaceAll(v, "\n", "\r\n")
	if v != "" && v[0] != ' ' && v[0] != '\t' {
		v = " " + v
	}
	s.fields = append(s.fields, field{name: name, value: v})
	return milter.RespContinue, nil
}

// Headers decides whether the message gets a seal; one that will not is
// accepted here, so the MTA sends no body for it.
func (s *session) Headers(_ textproto.MIMEHeader, m *milter.Modifier) (milter.Response, error) {
	s.queueID = m.Macros["i"]
	log := slog.With("queue_id", s.queueID)
	s.chain = collect(s.fields)
	switch {
	case s.chain.lastCV() == cvFail:
		// RFC 8617 5.1 step 2: a chain an earlier hop declared failed ends there.
		sealResults.WithLabelValues("chain_failed").Inc()
		log.Info("arc: not sealed, the last ARC-Seal says cv=fail", "instance", s.chain.n)
		return milter.RespAccept, nil
	case s.chain.n >= maxInstance:
		sealResults.WithLabelValues("instance_limit").Inc()
		log.Warn("arc: not sealed, the chain is at its last instance", "instance", s.chain.n)
		return milter.RespAccept, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	k, ok, err := s.keys.lookup(ctx, s.sealDomain)
	cancel()
	if err != nil {
		// Only a key never cached and unreadable now: the relay retries,
		// rather than sending a forward that strict DMARC would refuse.
		sealResults.WithLabelValues("tempfail_key").Inc()
		log.Warn("arc: tempfail, the key cannot be read", "domain", s.sealDomain, "err", err)
		return milter.RespTempFail, nil
	}
	if !ok {
		sealResults.WithLabelValues("no_key").Inc()
		log.Warn("arc: not sealed, no ARC key row for the seal domain", "domain", s.sealDomain)
		return milter.RespAccept, nil
	}
	s.key, s.sealing = k, true
	s.ours = newBodyHasher(true, -1)
	if s.chain.n > 0 && s.chain.broken == "" {
		t := s.chain.sets[s.chain.n].amsTags
		_, relaxed, cerr := parseCanon(t["c"])
		var limit int64 = -1
		if l, has := t["l"]; has {
			_, _ = fmt.Sscan(l, &limit)
		}
		if cerr == nil {
			s.theirs = newBodyHasher(relaxed, limit)
		}
	}
	return milter.RespContinue, nil
}

func (s *session) BodyChunk(chunk []byte, _ *milter.Modifier) (milter.Response, error) {
	if s.ours != nil {
		_, _ = s.ours.Write(chunk)
	}
	if s.theirs != nil {
		_, _ = s.theirs.Write(chunk)
	}
	return milter.RespContinue, nil
}

// authResults is the value of the first Authentication-Results this ADMD
// added, without the space after the colon; empty when there is none.
func (s *session) authResults() string {
	for _, f := range s.fields {
		if !strings.EqualFold(f.name, "Authentication-Results") {
			continue
		}
		v := strings.TrimLeft(f.value, " \t\r\n")
		head, _, _ := strings.Cut(relaxedValue(v), ";")
		id, _, _ := strings.Cut(strings.TrimSpace(head), " ")
		if strings.EqualFold(id, s.authservID) {
			return v
		}
	}
	return ""
}

// Body checks the chain and adds the new set on top: AS, AMS, AAR.
func (s *session) Body(m *milter.Modifier) (milter.Response, error) {
	defer s.reset()
	if q := m.Macros["i"]; q != "" {
		s.queueID = q
	}
	if !s.sealing {
		return milter.RespAccept, nil
	}
	log := slog.With("queue_id", s.queueID, "domain", s.key.domain)
	var theirSum []byte
	if s.theirs != nil {
		theirSum = s.theirs.Sum()
	}
	bodyFor := func(bool, int64) []byte { return theirSum }

	ctx, cancel := context.WithTimeout(context.Background(), s.dnsTimeout)
	cv, why, err := s.chain.validate(ctx, s.fields, bodyFor, s.dns)
	cancel()
	if err != nil {
		// A cv=fail seal would spoil the chain for good over a lookup that
		// may answer in a minute: the relay keeps the message and retries.
		sealResults.WithLabelValues("tempfail_dns").Inc()
		log.Warn("arc: tempfail, a key could not be looked up", "err", err)
		return milter.RespTempFail, nil
	}
	n := s.chain.n + 1
	results := s.authResults()
	if results == "" {
		log.Info("arc: no Authentication-Results from this ADMD, the AAR says none", "authserv_id", s.authservID)
	}
	aar, ams, as, err := seal(s.key, s.chain, s.fields, s.ours.Sum(), n, cv, s.authservID, results, s.now())
	if err != nil {
		sealResults.WithLabelValues("error").Inc()
		log.Error("arc: not sealed", "err", err)
		return milter.RespAccept, nil
	}
	for _, h := range [][2]string{{hdrAAR, aar}, {hdrAMS, ams}, {hdrAS, as}} {
		// The MTA writes the space after the colon itself.
		if err := m.InsertHeader(0, h[0], strings.TrimLeft(h[1], " ")); err != nil {
			sealResults.WithLabelValues("error").Inc()
			return nil, fmt.Errorf("arc: insert %s: %w", h[0], err)
		}
	}
	sealResults.WithLabelValues("sealed").Inc()
	chainResults.WithLabelValues(cv).Inc()
	log.Info("arc: sealed", "instance", n, "cv", cv, "why", why, "selector", s.key.selector)
	return milter.RespAccept, nil
}

func (s *session) Abort(*milter.Modifier) error {
	s.reset()
	return nil
}
