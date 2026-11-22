package app

import (
	"testing"

	"limier/internal/scanners"
)

func TestVulnRecordMalicious(t *testing.T) {
	tests := []struct {
		name      string
		v         scanners.OSVVuln
		malicious bool
		severity  string
	}{
		{"MAL id", scanners.OSVVuln{ID: "MAL-2024-1234"}, true, "critical"},
		{"GHSA malware alias", scanners.OSVVuln{ID: "GHSA-xxxx-yyyy-zzzz", Aliases: []string{"MAL-2025-1"}}, true, "critical"},
		{"plain CVE", scanners.OSVVuln{ID: "GHSA-aaaa-bbbb-cccc", Aliases: []string{"CVE-2024-1"}}, false, "unknown"},
	}
	for _, tt := range tests {
		r := vulnRecord(tt.v, enrichment{})
		if r.Malicious != tt.malicious || r.Severity != tt.severity {
			t.Errorf("%s: got malicious=%v severity=%s", tt.name, r.Malicious, r.Severity)
		}
	}
}
