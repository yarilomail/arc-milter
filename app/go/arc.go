package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// maxInstance is the highest ARC instance (RFC 8617 4.2.1).
const maxInstance = 50

// minRSABits is the smallest RSA key a signature may use (RFC 8301 3.2).
const minRSABits = 1024

const (
	hdrAAR = "ARC-Authentication-Results"
	hdrAMS = "ARC-Message-Signature"
	hdrAS  = "ARC-Seal"
)

// Chain results, the cv= values (RFC 8617 4.4).
const (
	cvNone = "none"
	cvPass = "pass"
	cvFail = "fail"
)

// errTempDNS is a key lookup that may answer later: the message is retried,
// never sealed cv=fail, which would spoil the chain for good.
var errTempDNS = errors.New("arc: temporary DNS failure")

// errSimpleUnverifiable is a newest AMS with simple header canonicalization
// that does not check. The MTA hands this milter the fields without the
// whitespace after the colon, so the bytes it signed may not be the ones
// rebuilt here: the chain may be sound, and a cv=fail seal on it could not
// be undone by anyone after. Such a message is left unsealed.
var errSimpleUnverifiable = errors.New("arc: a simple-canonicalized AMS does not check on the rebuilt fields")

// keyResolver returns the public key a selector publishes for a domain;
// a missing or revoked key is a permanent error, errTempDNS a temporary one.
type keyResolver interface {
	PublicKey(ctx context.Context, selector, domain string) (*rsa.PublicKey, error)
}

// arcSet is one instance's three fields.
type arcSet struct {
	aar, ams, as field
	amsTags      tags
	asTags       tags
}

// chain is the ARC sets a message arrived with, by instance.
type chain struct {
	sets map[int]*arcSet
	n    int // highest instance, 0 for none
	// highest is the highest i= of any ARC field that names one, read past a
	// broken field too, so a new set never repeats a number already there.
	highest int
	// broken says the fields do not form sets 1..n (RFC 8617 5.2 step 2).
	broken string
}

func instanceOf(f field) (int, error) {
	t, err := parseTags(f.value)
	if err != nil {
		return 0, err
	}
	// The AAR's tag-list ends at its first ";": only i= is read from it.
	i, err := strconv.Atoi(t["i"])
	if err != nil || i < 1 || i > maxInstance {
		return 0, fmt.Errorf("arc: %s i=%q", f.name, t["i"])
	}
	return i, nil
}

func aarInstance(f field) (int, error) {
	head, _, _ := strings.Cut(relaxedValue(f.value), ";")
	k, v, ok := strings.Cut(strings.TrimSpace(head), "=")
	if !ok || strings.TrimSpace(k) != "i" {
		return 0, fmt.Errorf("arc: %s has no leading i=", f.name)
	}
	i, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || i < 1 || i > maxInstance {
		return 0, fmt.Errorf("arc: %s i=%q", f.name, v)
	}
	return i, nil
}

// looseInstance reads an ARC field's i= without judging it, 0 when there is
// no number.
func looseInstance(f field) int {
	head := relaxedValue(f.value)
	for _, part := range strings.Split(head, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.TrimSpace(k) == "i" {
			if i, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && i > 0 {
				return i
			}
			return 0
		}
	}
	return 0
}

// collect gathers the ARC fields of a header block.
func collect(fields []field) chain {
	c := chain{sets: map[int]*arcSet{}}
	for _, f := range fields {
		if strings.EqualFold(f.name, hdrAAR) || strings.EqualFold(f.name, hdrAMS) || strings.EqualFold(f.name, hdrAS) {
			c.highest = max(c.highest, looseInstance(f))
		}
	}
	fail := func(why string) chain {
		c.broken = why
		return c
	}
	for _, f := range fields {
		var i int
		var err error
		switch {
		case strings.EqualFold(f.name, hdrAAR):
			i, err = aarInstance(f)
		case strings.EqualFold(f.name, hdrAMS), strings.EqualFold(f.name, hdrAS):
			i, err = instanceOf(f)
		default:
			continue
		}
		if err != nil {
			return fail(err.Error())
		}
		s := c.sets[i]
		if s == nil {
			s = &arcSet{}
			c.sets[i] = s
		}
		var slot *field
		switch {
		case strings.EqualFold(f.name, hdrAAR):
			slot = &s.aar
		case strings.EqualFold(f.name, hdrAMS):
			slot = &s.ams
		default:
			slot = &s.as
		}
		if slot.name != "" {
			return fail(fmt.Sprintf("two %s with i=%d", f.name, i))
		}
		*slot = f
		c.n = max(c.n, i)
	}
	for i := 1; i <= c.n; i++ {
		s := c.sets[i]
		if s == nil || s.aar.name == "" || s.ams.name == "" || s.as.name == "" {
			return fail(fmt.Sprintf("set %d is incomplete", i))
		}
		var err error
		if s.amsTags, err = parseTags(s.ams.value); err != nil {
			return fail(err.Error())
		}
		if s.asTags, err = parseTags(s.as.value); err != nil {
			return fail(err.Error())
		}
	}
	return c
}

// lastCV is the cv= of the highest ARC-Seal, empty without a chain.
func (c chain) lastCV() string {
	if c.n == 0 || c.broken != "" {
		return ""
	}
	return strings.ToLower(c.sets[c.n].asTags["cv"])
}

// validate is RFC 8617 5.2: the chain's state as this hop finds it. The
// body hash is that of the newest AMS's canonicalization, from bodyFor.
// errTempDNS comes back as an error, every other failure as cvFail and why.
func (c chain) validate(ctx context.Context, fields []field, bodyFor func(relaxed bool, limit int64) []byte, keys keyResolver) (string, string, error) {
	if c.broken != "" {
		return cvFail, c.broken, nil
	}
	if c.n == 0 {
		return cvNone, "", nil
	}
	if c.lastCV() == cvFail {
		return cvFail, fmt.Sprintf("ARC-Seal i=%d says cv=fail", c.n), nil
	}
	if why, err := verifyAMS(ctx, fields, c.sets[c.n], bodyFor, keys); err != nil || why != "" {
		if err == nil && strings.HasPrefix(why, "AMS i=") && strings.HasSuffix(why, "header bytes do not check") {
			return "", why, errSimpleUnverifiable
		}
		return cvFail, why, err
	}
	for i := c.n; i >= 1; i-- {
		cv := strings.ToLower(c.sets[i].asTags["cv"])
		if (i == 1 && cv != cvNone) || (i > 1 && cv != cvPass) {
			return cvFail, fmt.Sprintf("ARC-Seal i=%d has cv=%s", i, cv), nil
		}
		if why, err := verifyAS(ctx, c, i, keys); err != nil || why != "" {
			return cvFail, why, err
		}
	}
	return cvPass, "", nil
}

// selectHeaders picks the fields h= names, each from the bottom up, as
// RFC 6376 5.4.2 orders them; a name with no field left adds nothing.
func selectHeaders(fields []field, names []string, relaxed bool) string {
	used := make([]bool, len(fields))
	var b strings.Builder
	for _, n := range names {
		n = strings.TrimSpace(n)
		for i := len(fields) - 1; i >= 0; i-- {
			if !used[i] && strings.EqualFold(fields[i].name, n) {
				used[i] = true
				b.WriteString(canonHeader(fields[i], relaxed))
				break
			}
		}
	}
	return b.String()
}

func parseCanon(c string) (header, body bool, err error) {
	if c == "" {
		return false, false, nil
	}
	h, bd, _ := strings.Cut(strings.ToLower(c), "/")
	if bd == "" {
		bd = "simple"
	}
	for _, v := range []string{h, bd} {
		if v != "simple" && v != "relaxed" {
			return false, false, fmt.Errorf("arc: c=%s", c)
		}
	}
	return h == "relaxed", bd == "relaxed", nil
}

// verifyRSA checks a base64 signature over data with the selector's key.
func verifyRSA(ctx context.Context, keys keyResolver, t tags, data string) (string, error) {
	if strings.ToLower(t["a"]) != "rsa-sha256" {
		return fmt.Sprintf("a=%s is not rsa-sha256", t["a"]), nil
	}
	sig, err := base64.StdEncoding.DecodeString(noSpace(t["b"]))
	if err != nil {
		return "b= is not base64", nil
	}
	pub, err := keys.PublicKey(ctx, t["s"], t["d"])
	if errors.Is(err, errTempDNS) {
		return "", err
	}
	if err != nil {
		return fmt.Sprintf("key %s._domainkey.%s: %v", t["s"], t["d"], err), nil
	}
	if pub.N.BitLen() < minRSABits {
		return fmt.Sprintf("key %s._domainkey.%s has %d bits, under %d (RFC 8301)", t["s"], t["d"], pub.N.BitLen(), minRSABits), nil
	}
	sum := sha256.Sum256([]byte(data))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		return fmt.Sprintf("signature by %s._domainkey.%s does not verify", t["s"], t["d"]), nil
	}
	return "", nil
}

func verifyAMS(ctx context.Context, fields []field, s *arcSet, bodyFor func(bool, int64) []byte, keys keyResolver) (string, error) {
	t := s.amsTags
	hRelaxed, bRelaxed, err := parseCanon(t["c"])
	if err != nil {
		return err.Error(), nil
	}
	limit := int64(-1)
	if l, ok := t["l"]; ok {
		if limit, err = strconv.ParseInt(l, 10, 64); err != nil || limit < 0 {
			return fmt.Sprintf("AMS l=%s", l), nil
		}
	}
	bh, err := base64.StdEncoding.DecodeString(noSpace(t["bh"]))
	if err != nil || string(bodyFor(bRelaxed, limit)) != string(bh) {
		return fmt.Sprintf("AMS i=%s body hash does not match", t["i"]), nil
	}
	var names []string
	for _, n := range strings.Split(t["h"], ":") {
		if n = strings.TrimSpace(n); n != "" {
			if strings.EqualFold(n, hdrAS) {
				return "AMS signs ARC-Seal", nil
			}
			names = append(names, n)
		}
	}
	data := selectHeaders(fields, names, hRelaxed) +
		strings.TrimSuffix(canonHeader(field{s.ams.name, withoutB(s.ams.value)}, hRelaxed), "\r\n")
	why, err := verifyRSA(ctx, keys, t, data)
	if !hRelaxed && err == nil && strings.HasSuffix(why, "does not verify") {
		return fmt.Sprintf("AMS i=%s with simple header canonicalization: header bytes do not check", t["i"]), nil
	}
	return why, err
}

// sealInput is what ARC-Seal i=upto signs: every set from 1 up to it, AAR,
// AMS then AS, relaxed, the last AS without its b= value or final CRLF.
func sealInput(sets map[int]*arcSet, from, upto int) string {
	var b strings.Builder
	for i := from; i <= upto; i++ {
		s := sets[i]
		b.WriteString(relaxedHeader(s.aar))
		b.WriteString(relaxedHeader(s.ams))
		if i < upto {
			b.WriteString(relaxedHeader(s.as))
		}
	}
	b.WriteString(strings.TrimSuffix(relaxedHeader(field{sets[upto].as.name, withoutB(sets[upto].as.value)}), "\r\n"))
	return b.String()
}

func verifyAS(ctx context.Context, c chain, i int, keys keyResolver) (string, error) {
	return verifyRSA(ctx, keys, c.sets[i].asTags, sealInput(c.sets, 1, i))
}

// sealKey is what the milter seals with.
type sealKey struct {
	domain, selector string
	signer           *rsa.PrivateKey
}

// amsHeaders are the fields the AMS signs when present, once per field;
// From once more, so a From added later breaks it.
var amsHeaders = []string{
	"From", "Reply-To", "Subject", "Date", "To", "Cc",
	"Message-ID", "In-Reply-To", "References", "MIME-Version",
	"Content-Type", "Content-Transfer-Encoding",
	"List-Id", "List-Unsubscribe", "List-Unsubscribe-Post", "DKIM-Signature",
}

// signedNames lists each AMS field as many times as the message has it.
func signedNames(fields []field) []string {
	var names []string
	for _, n := range amsHeaders {
		for _, f := range fields {
			if strings.EqualFold(f.name, n) {
				names = append(names, n)
			}
		}
		if n == "From" {
			names = append(names, n)
		}
	}
	return names
}

func signRSA(k sealKey, data string) (string, error) {
	sum := sha256.Sum256([]byte(data))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k.signer, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("arc: sign: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// seal is the new set for instance n: the AAR from results, the AMS over
// fields and the relaxed body hash, and the AS with cv. A cv=fail seal
// covers only its own set (RFC 8617 5.1.2).
func seal(k sealKey, c chain, fields []field, bodyHash []byte, n int, cv, authservID, results string, now time.Time) (aar, ams, as string, err error) {
	ts := strconv.FormatInt(now.Unix(), 10)
	if results == "" {
		results = authservID + "; none"
	}
	aar = " i=" + strconv.Itoa(n) + "; " + results

	names := signedNames(fields)
	amsPairs := [][2]string{
		{"i", strconv.Itoa(n)}, {"a", "rsa-sha256"}, {"c", "relaxed/relaxed"},
		{"d", k.domain}, {"s", k.selector}, {"t", ts},
		{"h", strings.Join(names, ":")}, {"bh", base64.StdEncoding.EncodeToString(bodyHash)}, {"b", ""},
	}
	amsUnsigned := foldTags(len(hdrAMS), amsPairs)
	b, err := signRSA(k, selectHeaders(fields, names, true)+
		strings.TrimSuffix(relaxedHeader(field{hdrAMS, amsUnsigned}), "\r\n"))
	if err != nil {
		return "", "", "", err
	}
	ams = amsUnsigned + foldBase64(b)

	asPairs := [][2]string{
		{"i", strconv.Itoa(n)}, {"a", "rsa-sha256"}, {"t", ts}, {"cv", cv},
		{"d", k.domain}, {"s", k.selector}, {"b", ""},
	}
	asUnsigned := foldTags(len(hdrAS), asPairs)
	sets := map[int]*arcSet{}
	for i, s := range c.sets {
		sets[i] = s
	}
	sets[n] = &arcSet{aar: field{hdrAAR, aar}, ams: field{hdrAMS, ams}, as: field{hdrAS, asUnsigned}}
	from := 1
	if cv == cvFail {
		from = n
	}
	b, err = signRSA(k, sealInput(sets, from, n))
	if err != nil {
		return "", "", "", err
	}
	return aar, ams, asUnsigned + foldBase64(b), nil
}

// parsePublicKey reads a DKIM key record's p= (RFC 6376 3.6.1); an empty
// p= is a revoked key.
func parsePublicKey(record string) (*rsa.PublicKey, error) {
	t, err := parseTags(record)
	if err != nil {
		return nil, err
	}
	if k, ok := t["k"]; ok && !strings.EqualFold(k, "rsa") {
		return nil, fmt.Errorf("k=%s is not rsa", k)
	}
	p := noSpace(t["p"])
	if p == "" {
		return nil, errors.New("the key is revoked (empty p=)")
	}
	der, err := base64.StdEncoding.DecodeString(p)
	if err != nil {
		return nil, errors.New("p= is not base64")
	}
	if pk, err := x509.ParsePKIXPublicKey(der); err == nil {
		if r, ok := pk.(*rsa.PublicKey); ok {
			return r, nil
		}
		return nil, errors.New("p= is not an RSA key")
	}
	if r, err := x509.ParsePKCS1PublicKey(der); err == nil {
		return r, nil
	}
	return nil, errors.New("p= is not a public key")
}
