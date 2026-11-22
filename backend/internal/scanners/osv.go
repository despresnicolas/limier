package scanners

import (
	"sort"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
)

// OSVVuln is a vulnerability record in the OSV schema.
type OSVVuln struct {
	ID               string
	Aliases          []string
	Summary          string
	Details          string
	Published        time.Time
	Modified         time.Time
	Severity         []OSVSeverity
	Affected         []OSVAffected
	References       []OSVReference
	DatabaseSpecific map[string]any
}

type OSVSeverity struct {
	Type  string // CVSS_V2, CVSS_V3, CVSS_V4, Ubuntu...
	Score string // vector string for CVSS types
}

type OSVReference struct {
	Type string
	URL  string
}

type OSVPackage struct {
	Ecosystem string
	Name      string
	Purl      string
}

type OSVEvent struct {
	Introduced   string
	Fixed        string
	LastAffected string
	Limit        string
}

type OSVRange struct {
	Type   string // SEMVER, ECOSYSTEM, GIT
	Events []OSVEvent
}

type OSVAffected struct {
	Package           OSVPackage
	Severity          []OSVSeverity
	Ranges            []OSVRange
	Versions          []string
	DatabaseSpecific  map[string]any
	EcosystemSpecific map[string]any
}

// ParseOSVVuln parses a single OSV JSON record.
func ParseOSVVuln(data []byte) (OSVVuln, error) {
	v, err := decode(data)
	if err != nil {
		return OSVVuln{}, err
	}
	return osvFromAny(v), nil
}

func osvFromAny(v any) OSVVuln {
	out := OSVVuln{
		ID:               asStr(get(v, "id")),
		Aliases:          asStrs(get(v, "aliases")),
		Summary:          asStr(get(v, "summary")),
		Details:          asStr(get(v, "details")),
		Published:        parseTime(asStr(get(v, "published"))),
		Modified:         parseTime(asStr(get(v, "modified"))),
		Severity:         osvSeverities(get(v, "severity")),
		DatabaseSpecific: asObj(get(v, "database_specific")),
	}
	for _, r := range asArr(get(v, "references")) {
		out.References = append(out.References, OSVReference{
			Type: asStr(get(r, "type")),
			URL:  asStr(get(r, "url")),
		})
	}
	for _, a := range asArr(get(v, "affected")) {
		aff := OSVAffected{
			Package: OSVPackage{
				Ecosystem: asStr(get(a, "package", "ecosystem")),
				Name:      asStr(get(a, "package", "name")),
				Purl:      asStr(get(a, "package", "purl")),
			},
			Severity:          osvSeverities(get(a, "severity")),
			Versions:          asStrs(get(a, "versions")),
			DatabaseSpecific:  asObj(get(a, "database_specific")),
			EcosystemSpecific: asObj(get(a, "ecosystem_specific")),
		}
		for _, r := range asArr(get(a, "ranges")) {
			rng := OSVRange{Type: asStr(get(r, "type"))}
			for _, e := range asArr(get(r, "events")) {
				rng.Events = append(rng.Events, OSVEvent{
					Introduced:   asStr(get(e, "introduced")),
					Fixed:        asStr(get(e, "fixed")),
					LastAffected: asStr(get(e, "last_affected")),
					Limit:        asStr(get(e, "limit")),
				})
			}
			aff.Ranges = append(aff.Ranges, rng)
		}
		out.Affected = append(out.Affected, aff)
	}
	return out
}

func osvSeverities(v any) []OSVSeverity {
	var out []OSVSeverity
	for _, s := range asArr(v) {
		out = append(out, OSVSeverity{Type: asStr(get(s, "type")), Score: asStr(get(s, "score"))})
	}
	return out
}

func parseTime(s string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

var ghsaSeverityScores = map[string]float64{
	"CRITICAL": 9.5,
	"HIGH":     7.5,
	"MODERATE": 5.5,
	"MEDIUM":   5.5,
	"LOW":      2.5,
}

// CVSS returns the best available score: the highest computable CVSS v3
// vector (top-level, then per-affected), else the GHSA-style
// database_specific.severity label mapped to a representative score.
func (v OSVVuln) CVSS() (score float64, vector string, ok bool) {
	sevs := v.Severity
	for _, a := range v.Affected {
		sevs = append(sevs, a.Severity...)
	}
	for _, s := range sevs {
		if s.Type != "CVSS_V3" {
			continue
		}
		if sc, err := CVSS3BaseScore(s.Score); err == nil && (!ok || sc > score) {
			score, vector, ok = sc, s.Score, true
		}
	}
	if ok {
		return score, vector, true
	}
	label := strings.ToUpper(asStr(v.DatabaseSpecific["severity"]))
	if sc, found := ghsaSeverityScores[label]; found {
		return sc, "", true
	}
	return 0, "", false
}

// CVEs returns the CVE identifiers among the ID and aliases.
func (v OSVVuln) CVEs() []string {
	var out []string
	seen := map[string]bool{}
	for _, id := range append([]string{v.ID}, v.Aliases...) {
		if strings.HasPrefix(id, "CVE-") && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// Malicious tells whether the record is an OpenSSF malicious-package advisory: its ID or an alias
// starts with MAL- (GHSA malware advisories carry the MAL- id as an alias).
func (v OSVVuln) Malicious() bool {
	for _, id := range append([]string{v.ID}, v.Aliases...) {
		if strings.HasPrefix(id, "MAL-") {
			return true
		}
	}
	return false
}

// MinFixedVersion returns the smallest fixed version above installed among
// the ranges of the matching package that contain installed. When versions
// cannot be parsed as semver, it falls back to the first fixed event.
func (v OSVVuln) MinFixedVersion(ecosystem, name, installed string) string {
	inst, instErr := semver.NewVersion(installed)
	var best *semver.Version
	bestRaw, firstFixed := "", ""
	unparsed := instErr != nil

	for _, a := range v.Affected {
		if a.Package.Name != name || !strings.EqualFold(a.Package.Ecosystem, ecosystem) {
			continue
		}
		for _, r := range a.Ranges {
			if r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
				continue
			}
			for _, e := range r.Events {
				if e.Fixed != "" && firstFixed == "" {
					firstFixed = e.Fixed
				}
			}
			if instErr != nil {
				continue
			}
			fixed, affected, err := semverRangeFix(r.Events, inst)
			if err != nil {
				unparsed = true
				continue
			}
			if affected && fixed != nil && (best == nil || fixed.LessThan(best)) {
				best, bestRaw = fixed, fixed.Original()
			}
		}
	}
	if best == nil && unparsed {
		return firstFixed
	}
	return bestRaw
}

type semverEvent struct {
	kind string // introduced, fixed, last_affected, limit
	ver  *semver.Version
}

// semverRangeFix evaluates an OSV range for inst using the OSV algorithm
// (events sorted by version). fixed is the smallest fixed event greater
// than inst when inst is affected.
func semverRangeFix(events []OSVEvent, inst *semver.Version) (fixed *semver.Version, affected bool, err error) {
	zero := semver.New(0, 0, 0, "", "")
	var evs []semverEvent
	add := func(kind, raw string) {
		if raw == "" || err != nil {
			return
		}
		if raw == "0" {
			evs = append(evs, semverEvent{kind, zero})
			return
		}
		sv, perr := semver.NewVersion(raw)
		if perr != nil {
			err = perr
			return
		}
		evs = append(evs, semverEvent{kind, sv})
	}
	for _, e := range events {
		add("introduced", e.Introduced)
		add("fixed", e.Fixed)
		add("last_affected", e.LastAffected)
		add("limit", e.Limit)
	}
	if err != nil {
		return nil, false, err
	}
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].ver.LessThan(evs[j].ver) })

	for _, e := range evs {
		if e.ver.GreaterThan(inst) {
			break
		}
		switch e.kind {
		case "introduced":
			affected = true
		case "fixed", "limit":
			affected = false
		case "last_affected":
			affected = e.ver.Equal(inst)
		}
	}
	if !affected {
		return nil, false, nil
	}
	for _, e := range evs {
		if e.kind == "fixed" && e.ver.GreaterThan(inst) {
			return e.ver, true, nil
		}
	}
	return nil, true, nil
}
