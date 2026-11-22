package app

import (
	"reflect"
	"testing"

	"limier/internal/db/dbq"
)

func TestDropKnownKeepsOnlyNewVulns(t *testing.T) {
	pkgs := map[string]*pkgRef{
		"lodash@4.17.20": {Name: "lodash", Version: "4.17.20"},
		"lodash@4.17.21": {Name: "lodash", Version: "4.17.21"},
		"minimist@1.2.5": {Name: "minimist", Version: "1.2.5"},
	}
	keys := []string{"lodash@4.17.20", "lodash@4.17.21", "minimist@1.2.5"}
	ids := [][]string{{"GHSA-old", "GHSA-new"}, {"GHSA-old"}, {"GHSA-old"}}
	known := map[string]prevFinding{"GHSA-old|lodash": {}}

	got := dropKnown(keys, ids, pkgs, known)
	// Known on lodash (any version): dropped. Same ID on another package: new.
	want := [][]string{{"GHSA-new"}, nil, {"GHSA-old"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("dropKnown = %v, want %v", got, want)
	}
	if got := dropKnown(keys, ids, pkgs, nil); !reflect.DeepEqual(got, ids) {
		t.Fatalf("no known findings must keep everything, got %v", got)
	}
}

func TestVulnNewsNotice(t *testing.T) {
	var n vulnNews
	for _, v := range []dbq.UpsertVulnerabilityParams{
		{Severity: "high"},
		{Severity: "critical", Malicious: true}, // counted once, as malicious
		{Severity: "critical", InKev: true},
		{Severity: "critical"},
	} {
		n.add(v)
	}
	n.Projects = []string{"api", "front"}
	title, body := n.notice()
	if want := "Le détective a du nouveau : 4 nouvelles failles dans 2 projets"; title != want {
		t.Errorf("title = %q, want %q", title, want)
	}
	if want := "À regarder d'abord : 1 paquet malveillant, 1 faille déjà exploitée, 1 critique. Projets : api, front."; body != want {
		t.Errorf("body = %q, want %q", body, want)
	}

	one := vulnNews{Findings: 1, Projects: []string{"a", "b", "c", "d", "e"}}
	title, body = one.notice()
	if want := "Le détective a du nouveau : 1 nouvelle faille dans 5 projets"; title != want {
		t.Errorf("title = %q, want %q", title, want)
	}
	if want := "Projets : a, b, c, 2 autres."; body != want {
		t.Errorf("body = %q, want %q", body, want)
	}
}
