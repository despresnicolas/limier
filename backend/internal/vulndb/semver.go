package vulndb

import (
	"strings"

	"github.com/Masterminds/semver/v3"
)

// VersionsBehind classifies how far installed is behind latest: "major",
// "minor" or "patch" depending on the most significant differing component
// (a prerelease of the same major.minor.patch counts as "patch"). It returns
// "" when installed is up to date or newer, or when either version cannot be
// parsed.
func VersionsBehind(installed, latest string) string {
	iv, err := semver.NewVersion(strings.TrimSpace(installed))
	if err != nil {
		return ""
	}
	lv, err := semver.NewVersion(strings.TrimSpace(latest))
	if err != nil {
		return ""
	}
	if !iv.LessThan(lv) {
		return ""
	}
	switch {
	case iv.Major() != lv.Major():
		return "major"
	case iv.Minor() != lv.Minor():
		return "minor"
	default:
		return "patch"
	}
}

// BreakingSteps counts the breaking boundaries crossed from installed to target under semver:
// each major for >= 1.0.0, a minor change for 0.x, a patch change for 0.0.x. It returns 0 for a
// compatible update (or a downgrade), and -1 when either version cannot be parsed.
func BreakingSteps(installed, target string) int {
	iv, err := semver.NewVersion(strings.TrimSpace(installed))
	if err != nil {
		return -1
	}
	tv, err := semver.NewVersion(strings.TrimSpace(target))
	if err != nil {
		return -1
	}
	if !iv.LessThan(tv) {
		return 0
	}
	steps := int(tv.Major() - iv.Major())
	if iv.Major() == 0 {
		switch {
		case tv.Major() > 0:
			steps++ // 0.x -> 1.0 is breaking on top of the majors
		case iv.Minor() != tv.Minor():
			steps = 1
		case iv.Minor() == 0 && iv.Patch() != tv.Patch():
			steps = 1
		}
	}
	return steps
}
