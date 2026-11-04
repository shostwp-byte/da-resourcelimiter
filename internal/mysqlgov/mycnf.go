package mysqlgov

import (
	"os"
	"strings"

	"github.com/shostwp-byte/da-resourcelimiter/internal/config"
)

// MyCnfFinding reports whether a recommended Tier-1 MariaDB global protection key is present.
type MyCnfFinding struct {
	Key         string `json:"key"`
	Actual      string `json:"actual"`
	Recommended string `json:"recommended"`
	Present     bool   `json:"present"`
}

var tier1Recommended = []struct {
	key string
	val string
}{
	{"performance_schema", "ON"},
	{"max_connections", "500"},
	{"max_user_connections", "20"},
	{"max_statement_time", "15"},
	{"sort_buffer_size", "2M"},
	{"join_buffer_size", "2M"},
	{"read_buffer_size", "1M"},
	{"read_rnd_buffer_size", "1M"},
	{"tmp_table_size", "32M"},
	{"max_heap_table_size", "32M"},
}

// AuditMyCnf inspects /etc/my.cnf against Tier-1 per-thread memory safety recommendations.
func AuditMyCnf(path string) ([]MyCnfFinding, error) {
	if path == "" {
		path = "/etc/my.cnf"
	}
	kv, err := config.ParseKeyValueFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	normalized := make(map[string]string, len(kv))
	for k, v := range kv {
		normalized[strings.ToLower(strings.ReplaceAll(k, "-", "_"))] = v
	}

	findings := make([]MyCnfFinding, 0, len(tier1Recommended))
	for _, rec := range tier1Recommended {
		actual, ok := normalized[rec.key]
		findings = append(findings, MyCnfFinding{
			Key:         rec.key,
			Actual:      actual,
			Recommended: rec.val,
			Present:     ok,
		})
	}
	return findings, nil
}

// RecommendedMyCnfSnippet returns the ready-to-include Tier-1 MariaDB configuration block.
func RecommendedMyCnfSnippet() string {
	return `[mysqld]
# DA-ResourceLimiter Tier-1 Per-Thread Memory Protection
performance_schema = ON
max_connections = 500
max_user_connections = 20
max_statement_time = 15

sort_buffer_size = 2M
join_buffer_size = 2M
read_buffer_size = 1M
read_rnd_buffer_size = 1M

tmp_table_size = 32M
max_heap_table_size = 32M
`
}
