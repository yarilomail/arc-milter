package main

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// tags is a parsed tag-list (RFC 6376 3.2).
type tags map[string]string

var errTagList = errors.New("arc: malformed tag-list")

// parseTags reads "k=v; k=v"; a repeated tag or one without "=" is an error.
// Values keep inner whitespace except where the caller strips it.
func parseTags(v string) (tags, error) {
	out := tags{}
	for _, part := range strings.Split(relaxedValue(v), ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, val, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("%w: %q", errTagList, part)
		}
		k = strings.TrimSpace(k)
		if _, dup := out[k]; dup {
			return nil, fmt.Errorf("%w: tag %s twice", errTagList, k)
		}
		out[k] = strings.TrimSpace(val)
	}
	return out, nil
}

// noSpace is a base64 value with the folding whitespace taken out.
func noSpace(v string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, v)
}

// bTag finds the b= tag's value, not bh=.
var bTag = regexp.MustCompile(`(^|;)([ \t\r\n]*b[ \t\r\n]*=)[^;]*`)

// withoutB is the field value with the b= value removed, as it is hashed.
func withoutB(v string) string { return bTag.ReplaceAllString(v, "$1$2") }

// foldTags joins tags in order for a field the milter adds, starting a new
// line when one would pass 76 columns. The leading space is the one after
// the colon; nameLen is the field name's length.
func foldTags(nameLen int, pairs [][2]string) string {
	var b strings.Builder
	col := nameLen + 1
	for i, p := range pairs {
		tag := p[0] + "=" + p[1] + ";"
		if i == len(pairs)-1 {
			tag = strings.TrimSuffix(tag, ";")
		}
		if i > 0 && col+1+len(tag) > 76 {
			b.WriteString("\r\n\t")
			col = 8
		} else {
			b.WriteString(" ")
			col++
		}
		b.WriteString(tag)
		col += len(tag)
	}
	return b.String()
}

// foldBase64 puts a signature on lines of its own; FWS inside b= is ignored.
func foldBase64(s string) string {
	const width = 72
	var b strings.Builder
	for len(s) > 0 {
		n := min(width, len(s))
		b.WriteString("\r\n\t ")
		b.WriteString(s[:n])
		s = s[n:]
	}
	return b.String()
}
