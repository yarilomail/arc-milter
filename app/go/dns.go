package main

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net"
	"strings"
)

// dnsKeys reads public keys from <selector>._domainkey.<domain> TXT records.
// Only "no such name" is permanent; any other failure, a timeout or the
// message's deadline included, is errTempDNS.
type dnsKeys struct {
	lookupTXT func(ctx context.Context, name string) ([]string, error)
}

func newDNSKeys(r *net.Resolver) *dnsKeys { return &dnsKeys{lookupTXT: r.LookupTXT} }

func (d *dnsKeys) PublicKey(ctx context.Context, selector, domain string) (*rsa.PublicKey, error) {
	if selector == "" || domain == "" {
		return nil, errors.New("no s= or d=")
	}
	name := selector + "._domainkey." + strings.TrimSuffix(domain, ".")
	txts, err := d.lookupTXT(ctx, name)
	if err != nil {
		var de *net.DNSError
		if errors.As(err, &de) && de.IsNotFound {
			return nil, fmt.Errorf("no key record at %s", name)
		}
		dnsLookupErrors.Inc()
		return nil, fmt.Errorf("%w: %s: %w", errTempDNS, name, err)
	}
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
