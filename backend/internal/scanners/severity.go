package scanners

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// NormalizeSeverity maps tool-specific severity labels to
// "critical", "high", "medium", "low" or "unknown".
// Numeric strings are treated as CVSS scores.
func NormalizeSeverity(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "critical":
		return "critical"
	case "high", "important", "error":
		return "high"
	case "medium", "moderate", "warning", "warn":
		return "medium"
	case "low", "negligible", "info", "minor":
		return "low"
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return SeverityFromScore(f)
	}
	return "unknown"
}

// SeverityFromScore maps a CVSS score to its qualitative band.
func SeverityFromScore(score float64) string {
	switch {
	case score >= 9:
		return "critical"
	case score >= 7:
		return "high"
	case score >= 4:
		return "medium"
	case score > 0:
		return "low"
	}
	return "unknown"
}

var cvss3Weights = map[string]map[string]float64{
	"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
	"AC": {"L": 0.77, "H": 0.44},
	"UI": {"N": 0.85, "R": 0.62},
	"C":  {"H": 0.56, "L": 0.22, "N": 0},
	"I":  {"H": 0.56, "L": 0.22, "N": 0},
	"A":  {"H": 0.56, "L": 0.22, "N": 0},
}

// CVSS3BaseScore computes the base score of a CVSS v3.0 or v3.1 vector.
// Temporal and environmental metrics are ignored.
func CVSS3BaseScore(vector string) (float64, error) {
	parts := strings.Split(strings.TrimSpace(vector), "/")
	if len(parts) == 0 {
		return 0, errors.New("cvss: empty vector")
	}
	var v31 bool
	switch parts[0] {
	case "CVSS:3.1":
		v31 = true
	case "CVSS:3.0":
	default:
		return 0, fmt.Errorf("cvss: unsupported version %q", parts[0])
	}
	m := map[string]string{}
	for _, p := range parts[1:] {
		k, val, ok := strings.Cut(p, ":")
		if !ok {
			return 0, fmt.Errorf("cvss: malformed metric %q", p)
		}
		m[k] = val
	}

	scope := m["S"]
	if scope != "U" && scope != "C" {
		return 0, fmt.Errorf("cvss: invalid scope %q", scope)
	}
	changed := scope == "C"

	w := map[string]float64{}
	for metric, values := range cvss3Weights {
		f, ok := values[m[metric]]
		if !ok {
			return 0, fmt.Errorf("cvss: invalid %s value %q", metric, m[metric])
		}
		w[metric] = f
	}
	var pr float64
	switch m["PR"] {
	case "N":
		pr = 0.85
	case "L":
		pr = 0.62
		if changed {
			pr = 0.68
		}
	case "H":
		pr = 0.27
		if changed {
			pr = 0.5
		}
	default:
		return 0, fmt.Errorf("cvss: invalid PR value %q", m["PR"])
	}

	iss := 1 - (1-w["C"])*(1-w["I"])*(1-w["A"])
	var impact float64
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, nil
	}
	expl := 8.22 * w["AV"] * w["AC"] * pr * w["UI"]
	base := impact + expl
	if changed {
		base *= 1.08
	}
	base = math.Min(base, 10)

	if v31 {
		return roundup31(base), nil
	}
	return math.Ceil(base*10) / 10, nil
}

// roundup31 is the floating-point safe Roundup from CVSS v3.1 Appendix A.
func roundup31(x float64) float64 {
	i := int64(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return float64(i/10000+1) / 10
}
