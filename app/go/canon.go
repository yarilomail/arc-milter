package main

import (
	"bytes"
	"crypto/sha256"
	"hash"
	"strings"
)

// field is one header field as the MTA passed it: the value starts with the
// whitespace after the colon and folds with CRLF.
type field struct{ name, value string }

// raw is the field as it stands in the message.
func (f field) raw() string { return f.name + ":" + f.value }

// relaxedHeader is RFC 6376 3.4.2: lower-case name, unfolded value with
// whitespace runs reduced to one space and trimmed at both ends.
func relaxedHeader(f field) string {
	return strings.ToLower(strings.TrimRight(f.name, " \t")) + ":" + relaxedValue(f.value) + "\r\n"
}

func relaxedValue(v string) string {
	v = strings.ReplaceAll(v, "\r\n", "")
	v = strings.ReplaceAll(v, "\n", "")
	var b strings.Builder
	space := false
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == ' ' || c == '\t' {
			space = true
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteByte(c)
	}
	return b.String()
}

// simpleHeader is RFC 6376 3.4.1: the field unchanged.
func simpleHeader(f field) string { return f.raw() + "\r\n" }

func canonHeader(f field, relaxed bool) string {
	if relaxed {
		return relaxedHeader(f)
	}
	return simpleHeader(f)
}

// bodyHasher hashes a body as it streams, canonicalized by RFC 6376 3.4.3
// (simple) or 3.4.4 (relaxed). Empty lines are held until a line with
// content follows, since trailing ones are not hashed; limit is the l= tag,
// negative when absent.
type bodyHasher struct {
	h       hash.Hash
	relaxed bool
	limit   int64
	written int64
	line    []byte
	empty   int
	any     bool
}

func newBodyHasher(relaxed bool, limit int64) *bodyHasher {
	return &bodyHasher{h: sha256.New(), relaxed: relaxed, limit: limit}
}

func (b *bodyHasher) Write(p []byte) (int, error) {
	for _, c := range p {
		b.line = append(b.line, c)
		if c == '\n' {
			b.endLine(true)
		}
	}
	return len(p), nil
}

func (b *bodyHasher) emit(p []byte) {
	if b.limit >= 0 {
		left := b.limit - b.written
		if left <= 0 {
			return
		}
		if int64(len(p)) > left {
			p = p[:left]
		}
	}
	b.written += int64(len(p))
	b.h.Write(p)
}

// endLine takes the held line; terminated says it ended with LF.
func (b *bodyHasher) endLine(terminated bool) {
	l := b.line
	b.line = b.line[:0]
	l = bytes.TrimSuffix(l, []byte("\n"))
	l = bytes.TrimSuffix(l, []byte("\r"))
	if !terminated && len(l) == 0 {
		return
	}
	if b.relaxed {
		l = relaxedBodyLine(l)
	}
	if len(l) == 0 {
		b.empty++
		return
	}
	for ; b.empty > 0; b.empty-- {
		b.emit([]byte("\r\n"))
	}
	b.emit(l)
	b.emit([]byte("\r\n"))
	b.any = true
}

func relaxedBodyLine(l []byte) []byte {
	out := make([]byte, 0, len(l))
	space := false
	for _, c := range l {
		if c == ' ' || c == '\t' {
			space = true
			continue
		}
		if space {
			out = append(out, ' ')
		}
		space = false
		out = append(out, c)
	}
	return out
}

// Sum ends the body: a simple body with no content hashes as one CRLF, a
// relaxed one as nothing.
func (b *bodyHasher) Sum() []byte {
	if len(b.line) > 0 {
		b.endLine(false)
	}
	if !b.any && !b.relaxed {
		b.emit([]byte("\r\n"))
	}
	return b.h.Sum(nil)
}
