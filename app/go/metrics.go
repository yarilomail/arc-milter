package main

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	sealResults = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "arc_messages_total", Help: "Messages seen, by result: sealed, chain_failed (an earlier seal says cv=fail), instance_limit, no_key, tempfail_key, tempfail_dns, error.",
	}, []string{"result"})
	chainResults = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "arc_chain_total", Help: "Sealed messages, by the cv= this hop found: none, pass, fail.",
	}, []string{"cv"})
	dnsLookupErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "arc_dns_temporary_errors_total", Help: "Key lookups that failed for a reason other than a missing name.",
	})
	keysLoaded = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "arc_keys_loaded", Help: "Domains with a key in the cache.",
	})
	cacheLookups = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "arc_key_cache_lookups_total", Help: "Key lookups, by result: hit, negative_hit (cached as keyless), stale (served while read again), miss.",
	}, []string{"result"})
	keyFetchErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "arc_key_fetch_errors_total", Help: "Key fetches that failed, by stage: db, vault, parse.",
	}, []string{"stage"})
)

func metricsMux(ready func() bool) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready() {
			http.Error(w, "database or Vault not reached yet", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return mux
}
