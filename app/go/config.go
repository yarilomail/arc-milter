package main

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	defaultListenAddr   = "0.0.0.0:8893"
	defaultMetricsAddr  = "0.0.0.0:8081"
	defaultSelector     = "arc"
	defaultCacheSize    = 100
	defaultCacheTTL     = 600
	defaultCacheMissTTL = 60
	defaultDBMaxOpen    = 4
	defaultDNSTimeout   = 10
	// defaultDNSGrace is how long a key name may keep failing temporarily
	// before it counts as failed: 4 hours, well inside Postfix's 5-day queue.
	defaultDNSGrace = 14400
	// Postfix keeps one milter connection for a whole SMTP session and is
	// silent on it while the client sends, so the read timeout outlasts any
	// session; it only frees connections that nobody will use again.
	defaultMilterRead  = 3600
	defaultMilterWrite = 60
	defaultSATokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

// validDomain is a domain name: labels of letters, digits and hyphens.
var validDomain = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// validSelector is one DNS label.
var validSelector = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

type config struct {
	listenAddr  string
	metricsAddr string

	dbDriver  string // postgres | mysql
	dbDSN     string
	dbMaxOpen int
	query     string

	decrypt string // vault | none
	vault   vaultConfig

	cacheSize    int
	cacheTTL     time.Duration
	cacheMissTTL time.Duration

	milterRead  time.Duration
	milterWrite time.Duration

	// sealDomain is SEAL_DOMAIN, the d= of every seal; selector is its
	// ARC_SELECTOR, a key row of its own beside the domain's DKIM row.
	sealDomain string
	selector   string
	// authservID is AUTHSERV_ID: the Authentication-Results this ADMD's MX
	// adds, copied into the AAR.
	authservID string
	dnsTimeout time.Duration
	// dnsGrace is DNS_TEMPFAIL_GRACE_SECONDS: past it a name that keeps
	// failing is a failed signature, not one more retry.
	dnsGrace time.Duration
	redis    redisConfig
}

// defaultQueries read the seal domain's newest row with the ARC selector,
// the domain compared without case and surrounding spaces; the
// placeholders are the driver's, the domain and then the selector.
var defaultQueries = map[string]string{
	"postgres": "SELECT domain, selector, private_key_enc FROM dkim WHERE lower(trim(domain)) = $1 AND selector = $2 ORDER BY created_at DESC, id DESC LIMIT 1",
	"mysql":    "SELECT domain, selector, private_key_enc FROM dkim WHERE lower(trim(domain)) = ? AND selector = ? ORDER BY created_at DESC, id DESC LIMIT 1",
}

// positive reads a whole number above zero.
func positive(name string, def int) (int, error) {
	v, err := strconv.Atoi(env(name, strconv.Itoa(def)))
	if err != nil || v <= 0 {
		return 0, fmt.Errorf("config: %s %q: a whole number above 0", name, os.Getenv(name))
	}
	return v, nil
}

// redisConfig is where the first failure of each DNS name is kept.
type redisConfig struct {
	addr             string
	sentinelAddrs    []string
	sentinelMaster   string
	sentinelUser     string
	sentinelPassword string
	user, password   string
	db               int
	prefix           string
}

type vaultConfig struct {
	addr        string
	authPath    string
	role        string
	tokenFile   string
	caCert      string
	transitPath string
	transitKey  string
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func seconds(name string, def int) (time.Duration, error) {
	v, err := positive(name, def)
	return time.Duration(v) * time.Second, err
}

func loadConfig() (config, error) {
	c := config{
		listenAddr:  env("LISTEN_ADDR", defaultListenAddr),
		metricsAddr: env("METRICS_ADDR", defaultMetricsAddr),
		dbDriver:    strings.ToLower(env("DB_DRIVER", "postgres")),
		dbDSN:       os.Getenv("DB_DSN"),
		decrypt:     strings.ToLower(env("KEY_DECRYPT", "vault")),
		sealDomain:  strings.ToLower(strings.TrimSpace(os.Getenv("SEAL_DOMAIN"))),
		selector:    strings.ToLower(strings.TrimSpace(env("ARC_SELECTOR", defaultSelector))),
		authservID:  strings.TrimSpace(os.Getenv("AUTHSERV_ID")),
		vault: vaultConfig{
			addr:        os.Getenv("VAULT_ADDR"),
			authPath:    env("VAULT_AUTH_PATH", "kubernetes"),
			role:        os.Getenv("VAULT_ROLE"),
			tokenFile:   env("VAULT_SA_TOKEN_FILE", defaultSATokenFile),
			caCert:      os.Getenv("VAULT_CACERT"),
			transitPath: env("VAULT_TRANSIT_PATH", "transit"),
			transitKey:  env("VAULT_TRANSIT_KEY", "dkim"),
		},
	}
	var err error
	if c.cacheSize, err = positive("KEY_CACHE_SIZE", defaultCacheSize); err != nil {
		return c, err
	}
	if c.cacheTTL, err = seconds("KEY_CACHE_TTL_SECONDS", defaultCacheTTL); err != nil {
		return c, err
	}
	if c.cacheMissTTL, err = seconds("KEY_CACHE_MISS_TTL_SECONDS", defaultCacheMissTTL); err != nil {
		return c, err
	}
	if c.dbMaxOpen, err = positive("DB_MAX_OPEN_CONNS", defaultDBMaxOpen); err != nil {
		return c, err
	}
	if c.milterRead, err = seconds("MILTER_READ_TIMEOUT_SECONDS", defaultMilterRead); err != nil {
		return c, err
	}
	if c.milterWrite, err = seconds("MILTER_WRITE_TIMEOUT_SECONDS", defaultMilterWrite); err != nil {
		return c, err
	}
	if c.dnsTimeout, err = seconds("DNS_TIMEOUT_SECONDS", defaultDNSTimeout); err != nil {
		return c, err
	}
	if c.dnsGrace, err = seconds("DNS_TEMPFAIL_GRACE_SECONDS", defaultDNSGrace); err != nil {
		return c, err
	}
	if !validDomain.MatchString(c.sealDomain) {
		return c, fmt.Errorf("config: SEAL_DOMAIN %q: a domain name is required", c.sealDomain)
	}
	if !validSelector.MatchString(c.selector) {
		return c, fmt.Errorf("config: ARC_SELECTOR %q: one DNS label", c.selector)
	}
	if c.authservID == "" || strings.ContainsAny(c.authservID, " \t;") {
		return c, fmt.Errorf("config: AUTHSERV_ID %q: the MX's authserv-id is required", c.authservID)
	}
	if c.redis, err = loadRedis(); err != nil {
		return c, err
	}
	def, ok := defaultQueries[c.dbDriver]
	if !ok {
		return c, fmt.Errorf("config: DB_DRIVER %q: postgres or mysql", c.dbDriver)
	}
	c.query = env("ARC_SQL_QUERY", def)
	if c.dbDSN == "" {
		return c, fmt.Errorf("config: DB_DSN is required")
	}
	switch c.decrypt {
	case "none":
	case "vault":
		if c.vault.addr == "" || c.vault.role == "" {
			return c, fmt.Errorf("config: KEY_DECRYPT=vault needs VAULT_ADDR and VAULT_ROLE")
		}
	default:
		return c, fmt.Errorf("config: KEY_DECRYPT %q: vault or none", c.decrypt)
	}
	return c, nil
}

// loadRedis reads one address (REDIS_ADDR) or Sentinels (REDIS_SENTINEL_ADDRS,
// comma-separated, with REDIS_SENTINEL_MASTER); the key prefix is required, so
// two installations on one Redis never share a key.
func loadRedis() (redisConfig, error) {
	r := redisConfig{
		addr:             strings.TrimSpace(os.Getenv("REDIS_ADDR")),
		sentinelMaster:   strings.TrimSpace(os.Getenv("REDIS_SENTINEL_MASTER")),
		sentinelUser:     os.Getenv("REDIS_SENTINEL_USERNAME"),
		sentinelPassword: os.Getenv("REDIS_SENTINEL_PASSWORD"),
		user:             os.Getenv("REDIS_USERNAME"),
		password:         os.Getenv("REDIS_PASSWORD"),
		prefix:           os.Getenv("REDIS_KEY_PREFIX"),
	}
	for _, a := range strings.Split(os.Getenv("REDIS_SENTINEL_ADDRS"), ",") {
		if a = strings.TrimSpace(a); a != "" {
			r.sentinelAddrs = append(r.sentinelAddrs, a)
		}
	}
	db, err := strconv.Atoi(env("REDIS_DB", "0"))
	if err != nil || db < 0 {
		return r, fmt.Errorf("config: REDIS_DB %q: a whole number of 0 or more", os.Getenv("REDIS_DB"))
	}
	r.db = db
	switch {
	case r.addr != "" && len(r.sentinelAddrs) > 0:
		return r, fmt.Errorf("config: REDIS_ADDR and REDIS_SENTINEL_ADDRS: one or the other")
	case r.addr == "" && len(r.sentinelAddrs) == 0:
		return r, fmt.Errorf("config: REDIS_ADDR or REDIS_SENTINEL_ADDRS is required")
	case len(r.sentinelAddrs) > 0 && r.sentinelMaster == "":
		return r, fmt.Errorf("config: REDIS_SENTINEL_ADDRS needs REDIS_SENTINEL_MASTER")
	case strings.TrimSpace(r.prefix) == "":
		return r, fmt.Errorf("config: REDIS_KEY_PREFIX is required")
	}
	return r, nil
}
