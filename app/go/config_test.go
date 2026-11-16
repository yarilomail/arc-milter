package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// valuesScalars reads values.yaml as dotted keys and scalar values.
func valuesScalars(t *testing.T, path string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	type level struct {
		indent int
		key    string
	}
	var stack []level
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimLeft(line, " ")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "- ") {
			continue
		}
		indent := len(line) - len(trimmed)
		k, v, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		for len(stack) > 0 && stack[len(stack)-1].indent >= indent {
			stack = stack[:len(stack)-1]
		}
		var parts []string
		for _, l := range stack {
			parts = append(parts, l.key)
		}
		parts = append(parts, k)
		if v = strings.TrimSpace(v); v == "" {
			stack = append(stack, level{indent, k})
			continue
		}
		out[strings.Join(parts, ".")] = v
	}
	return out
}
func TestChartNamesFollowTheRelease(t *testing.T) {
	files, err := filepath.Glob("../../helm/templates/*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatalf("templates: %v %v", files, err)
	}
	fixed := regexp.MustCompile(`(?m)^\s*(name|app|serviceAccountName|commonName|- ): ?arc-milter\s*$`)
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range fixed.FindAll(raw, -1) {
			if strings.TrimSpace(string(m)) == "- name: arc-milter" {
				continue // the container's name, not a resource
			}
			t.Errorf("%s: %q is fixed, not {{ .Release.Name }}", filepath.Base(f), strings.TrimSpace(string(m)))
		}
	}
}

// Every default the chart sets is the code's, and reaches the container.
func TestChartDefaultsMatchTheCode(t *testing.T) {
	values := valuesScalars(t, "../../helm/values.yaml")
	tmpl, err := os.ReadFile("../../helm/templates/deployment.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if values["selector"] != defaultSelector {
		t.Errorf("selector = %q in values.yaml, %q in the code", values["selector"], defaultSelector)
	}
	for _, tc := range []struct {
		value, env string
		want       int
	}{
		{"keyCache.size", "KEY_CACHE_SIZE", defaultCacheSize},
		{"keyCache.ttlSeconds", "KEY_CACHE_TTL_SECONDS", defaultCacheTTL},
		{"keyCache.missTtlSeconds", "KEY_CACHE_MISS_TTL_SECONDS", defaultCacheMissTTL},
		{"db.maxOpenConns", "DB_MAX_OPEN_CONNS", defaultDBMaxOpen},
		{"dnsTimeoutSeconds", "DNS_TIMEOUT_SECONDS", defaultDNSTimeout},
		{"dnsTempfailGraceSeconds", "DNS_TEMPFAIL_GRACE_SECONDS", defaultDNSGrace},
		{"milterReadTimeoutSeconds", "MILTER_READ_TIMEOUT_SECONDS", defaultMilterRead},
		{"milterWriteTimeoutSeconds", "MILTER_WRITE_TIMEOUT_SECONDS", defaultMilterWrite},
	} {
		got, ok := values[tc.value]
		if !ok {
			t.Errorf("%s not in values.yaml", tc.value)
			continue
		}
		if got != strconv.Itoa(tc.want) {
			t.Errorf("%s = %s in values.yaml, %d in the code", tc.value, got, tc.want)
		}
		wire := regexp.MustCompile(`- name: ` + tc.env + `\n\s+value: \{\{ \.Values\.` + regexp.QuoteMeta(tc.value) + ` \| quote \}\}`)
		if !wire.Match(tmpl) {
			t.Errorf("deployment.yaml does not pass %s as %s", tc.value, tc.env)
		}
	}
	for _, env := range []string{"SEAL_DOMAIN", "ARC_SELECTOR", "AUTHSERV_ID"} {
		if !strings.Contains(string(tmpl), "- name: "+env+"\n") {
			t.Errorf("deployment.yaml does not set %s", env)
		}
	}
}

// The key query reads only the ARC selector's row: the domain's DKIM row,
// newer or not, is never taken for the seal.
func TestDefaultQueriesTakeOnlyTheARCRow(t *testing.T) {
	for driver, q := range defaultQueries {
		want := map[string]string{"postgres": "AND selector = $2", "mysql": "AND selector = ?"}[driver]
		if !strings.Contains(q, want) || !strings.Contains(q, "ORDER BY created_at DESC, id DESC LIMIT 1") {
			t.Errorf("%s: %s", driver, q)
		}
	}
}

func TestLoadConfig(t *testing.T) {
	base := map[string]string{"SEAL_DOMAIN": "Fwd.Example", "AUTHSERV_ID": "mx.example", "DB_DSN": "x", "KEY_DECRYPT": "none"}
	for _, tc := range []struct {
		name string
		set  map[string]string
		ok   bool
	}{
		{"defaults", nil, true},
		{"no seal domain", map[string]string{"SEAL_DOMAIN": ""}, false},
		{"seal domain not a name", map[string]string{"SEAL_DOMAIN": "fwd example"}, false},
		{"no authserv-id", map[string]string{"AUTHSERV_ID": ""}, false},
		{"authserv-id with a space", map[string]string{"AUTHSERV_ID": "mx example"}, false},
		{"selector of two labels", map[string]string{"ARC_SELECTOR": "a.b"}, false},
		{"DNS timeout 0", map[string]string{"DNS_TIMEOUT_SECONDS": "0"}, false},
		{"vault without an address", map[string]string{"KEY_DECRYPT": "vault"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range base {
				t.Setenv(k, v)
			}
			for k, v := range tc.set {
				t.Setenv(k, v)
			}
			c, err := loadConfig()
			if (err == nil) != tc.ok {
				t.Fatalf("err %v, ok want %v", err, tc.ok)
			}
			if tc.ok && (c.sealDomain != "fwd.example" || c.selector != "arc" || c.dnsTimeout.Seconds() != defaultDNSTimeout) {
				t.Errorf("config %+v", c)
			}
		})
	}
}
