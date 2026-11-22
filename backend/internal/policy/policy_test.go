package policy

import (
	"testing"
)

func TestPriority(t *testing.T) {
	w := *DefaultRules().Weights
	f := false
	tests := []struct {
		name string
		in   PriorityInput
		want float64
	}{
		{"max", PriorityInput{CVSS: 10, EPSS: 1, InKEV: true, Direct: true}, 100},
		{"direct no kev", PriorityInput{CVSS: 9.8, EPSS: 0.5, Direct: true}, 71.3},
		{"transitive", PriorityInput{CVSS: 5, EPSS: 0, Direct: false}, 24},
		{"unreachable direct", PriorityInput{CVSS: 10, EPSS: 0, Reachable: &f, Direct: true}, 18},
		{"unreachable transitive", PriorityInput{CVSS: 10, Reachable: &f}, 14.4},
		{"malicious ignores reach and depth", PriorityInput{Malicious: true, Reachable: &f}, 100},
	}
	for _, tt := range tests {
		if got := Priority(w, tt.in); got != tt.want {
			t.Errorf("%s: got %v want %v", tt.name, got, tt.want)
		}
	}
}

func TestEffectiveRules(t *testing.T) {
	g := Rules{MaxDependencyAgeDays: 100}
	p := Rules{MaxDependencyAgeDays: 365}
	e := Effective(g, p)
	if e.MaxDependencyAgeDays != 365 || e.Weights.CVSS != 6 {
		t.Fatalf("unexpected merge: %+v", e)
	}
}

func TestRiskScore(t *testing.T) {
	if RiskScore(nil) != 0 {
		t.Fatal("empty")
	}
	if r := RiskScore([]float64{100, 100, 100}); r != 100 {
		t.Fatalf("got %v", r)
	}
	if SecurityGrade(5) != "A" || SecurityGrade(90) != "E" {
		t.Fatal("grades")
	}
}

func TestMinReleaseAgeDays(t *testing.T) {
	if d := Effective(Rules{}, Rules{}).MinReleaseAgeDays; d == nil || *d != 3 {
		t.Fatalf("default: got %v want 3", d)
	}
	g, err := ParseRules([]byte(`{"min_release_age_days":7}`))
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParseRules([]byte(`{"min_release_age_days":0}`))
	if err != nil {
		t.Fatal(err)
	}
	if d := *Effective(g, Rules{}).MinReleaseAgeDays; d != 7 {
		t.Fatalf("global: got %d want 7", d)
	}
	if d := *Effective(g, p).MinReleaseAgeDays; d != 0 {
		t.Fatalf("project 0 must disable: got %d", d)
	}
	for _, n := range []int{-1, MaxMinReleaseAgeDays + 1} {
		if (Rules{MinReleaseAgeDays: &n}).Validate() == nil {
			t.Errorf("%d: want an error", n)
		}
	}
	for _, n := range []int{0, MaxMinReleaseAgeDays} {
		if err := (Rules{MinReleaseAgeDays: &n}).Validate(); err != nil {
			t.Errorf("%d: %v", n, err)
		}
	}
}
