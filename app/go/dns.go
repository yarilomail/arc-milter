package main

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// maxFailingNames bounds the memory of names that keep failing.
const maxFailingNames = 10000

// dnsKeys reads public keys from <selector>._domainkey.<domain> TXT records.
// "No such name" is permanent. Any other failure, a timeout or the message's
// deadline included, is errTempDNS while the name first failed less than
// grace ago; a name failing longer is taken as permanent (RFC 8617 5.2.1
// allows it), so a zone broken for days cannot hold a forward in the queue
// to the end of its life when it would go out without this milter.
type dnsKeys struct {
	lookupTXT func(ctx context.Context, name string) ([]string, error)
	grace     time.Duration
	now       func() time.Time

	mu      sync.Mutex
	failing map[string]time.Time
}

func newDNSKeys(r *net.Resolver, grace time.Duration) *dnsKeys {
	return &dnsKeys{lookupTXT: r.LookupTXT, grace: grace, now: time.Now, failing: map[string]time.Time{}}
}

// failedSince records a temporary failure and says since when the name fails.
func (d *dnsKeys) failedSince(name string) time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	if first, ok := d.failing[name]; ok {
		return first
	}
	if len(d.failing) >= maxFailingNames {
		for n, t := range d.failing {
			if now.Sub(t) > d.grace {
				delete(d.failing, n)
			}
		}
		if len(d.failing) >= maxFailingNames {
			return now
		}
	}
	d.failing[name] = now
	return now
}

func (d *dnsKeys) answered(name string) {
	d.mu.Lock()
	delete(d.failing, name)
	d.mu.Unlock()
}

func (d *dnsKeys) PublicKey(ctx context.Context, selector, domain string) (*rsa.PublicKey, error) {
	if selector == "" || domain == "" {
		return nil, errors.New("no s= or d=")
	}
	name := strings.ToLower(selector + "._domainkey." + strings.TrimSuffix(domain, "."))
	txts, err := d.lookupTXT(ctx, name)
	if err != nil {
		var de *net.DNSError
		if errors.As(err, &de) && de.IsNotFound {
			d.answered(name)
			return nil, fmt.Errorf("no key record at %s", name)
		}
		dnsLookupErrors.Inc()
		if first := d.failedSince(name); d.now().Sub(first) >= d.grace {
			dnsGivenUp.Inc()
			return nil, fmt.Errorf("%s has failed since %s, longer than %s: %w", name, first.UTC().Format(time.RFC3339), d.grace, err)
		}
		return nil, fmt.Errorf("%w: %s: %w", errTempDNS, name, err)
	}
	d.answered(name)
	last := fmt.Errorf("no key record at %s", name)
	for _, t := range txts {
		k, err := parsePublicKey(t)
		if err == nil {
			return k, nil
		}
		last = err
	}
	return nil, last
}
