// Package policy holds global/project policy rules and the priority score (SPECS §5).
package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
)

// Rules are stored in policies.rules. A project policy overrides the global one field by field.
type Rules struct {
	MaxDependencyAgeDays int `json:"max_dependency_age_days,omitempty"`
	// MinReleaseAgeDays holds back fix targets published less than N days ago (like Renovate's
	// minimumReleaseAge): a hijacked release is usually spotted and unpublished within days.
	// A pointer because 0 (disabled) must override an inherited value.
	MinReleaseAgeDays *int     `json:"min_release_age_days,omitempty"`
	Weights           *Weights `json:"priority_weights,omitempty"`
}

// MaxMinReleaseAgeDays caps min_release_age_days: beyond it, security fixes would wait too long.
const MaxMinReleaseAgeDays = 90

type Weights struct {
	CVSS        float64 `json:"cvss"`
	EPSS        float64 `json:"epss"`
	KEV         float64 `json:"kev"`
	Unreachable float64 `json:"unreachable"`
	Transitive  float64 `json:"transitive"`
}

func DefaultRules() Rules {
	return Rules{
		MaxDependencyAgeDays: 730,
		MinReleaseAgeDays:    new(3),
		Weights:              &Weights{CVSS: 6, EPSS: 25, KEV: 15, Unreachable: 0.3, Transitive: 0.8},
	}
}

func ParseRules(raw []byte) (Rules, error) {
	var r Rules
	if len(raw) == 0 {
		return r, nil
	}
	err := json.Unmarshal(raw, &r)
	return r, err
}

func (r Rules) Validate() error {
	if r.MaxDependencyAgeDays < 0 {
		return errors.New("max_dependency_age_days must be >= 0")
	}
	if d := r.MinReleaseAgeDays; d != nil && (*d < 0 || *d > MaxMinReleaseAgeDays) {
		return fmt.Errorf("min_release_age_days must be within [0,%d]", MaxMinReleaseAgeDays)
	}
	if w := r.Weights; w != nil {
		if w.CVSS < 0 || w.EPSS < 0 || w.KEV < 0 || w.Unreachable < 0 || w.Unreachable > 1 || w.Transitive < 0 || w.Transitive > 1 {
			return errors.New("priority_weights: weights must be >= 0 and multipliers within [0,1]")
		}
	}
	return nil
}

// Effective merges defaults, global and project rules (later wins).
func Effective(global, project Rules) Rules {
	out := DefaultRules()
	for _, r := range []Rules{global, project} {
		if r.MaxDependencyAgeDays != 0 {
			out.MaxDependencyAgeDays = r.MaxDependencyAgeDays
		}
		if r.MinReleaseAgeDays != nil {
			out.MinReleaseAgeDays = r.MinReleaseAgeDays
		}
		if r.Weights != nil {
			out.Weights = r.Weights
		}
	}
	return out
}

// SeverityRank orders severities; -1 for unknown values.
func SeverityRank(s string) int {
	switch s {
	case "low":
		return 0
	case "medium":
		return 1
	case "high":
		return 2
	case "critical":
		return 3
	}
	return -1
}

// PriorityInput holds the finding attributes used by the score.
type PriorityInput struct {
	CVSS      float64
	EPSS      float64
	InKEV     bool
	Reachable *bool
	Direct    bool
	Malicious bool // known malicious package version: always 100
}

// Priority computes the 0..100 score of SPECS §5.
func Priority(w Weights, in PriorityInput) float64 {
	if in.Malicious {
		return 100
	}
	p := in.CVSS*w.CVSS + in.EPSS*w.EPSS
	if in.InKEV {
		p += w.KEV
	}
	if in.Reachable != nil && !*in.Reachable {
		p *= w.Unreachable
	}
	if !in.Direct {
		p *= w.Transitive
	}
	return math.Round(math.Min(math.Max(p, 0), 100)*10) / 10
}

// RiskScore aggregates open finding priorities of a project into a 0..100 score:
// the highest priority plus a volume bonus that shrinks as the top priority nears 100.
func RiskScore(priorities []float64) float64 {
	if len(priorities) == 0 {
		return 0
	}
	var top, sum float64
	for _, p := range priorities {
		top = math.Max(top, p)
		sum += p
	}
	bonus := math.Min(20, math.Log1p(sum)*2)
	return math.Round(math.Min(100, top+bonus*(1-top/100))*10) / 10
}

// SecurityGrade maps a risk score to a badge grade.
func SecurityGrade(risk float64) string {
	switch {
	case risk < 10:
		return "A"
	case risk < 30:
		return "B"
	case risk < 50:
		return "C"
	case risk < 70:
		return "D"
	}
	return "E"
}
