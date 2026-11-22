package httpapi

import (
	"testing"

	"limier/internal/db/dbq"
)

func TestGroupDrift(t *testing.T) {
	row := func(pid int64, name, version string, vulns int32) dbq.VersionDriftRowsRow {
		return dbq.VersionDriftRowsRow{ProjectID: pid, ProjectPath: "/p" + string(rune('0'+pid)), Name: name, Version: version, LatestVersion: "9.0.0", OpenVulns: vulns}
	}
	rows := []dbq.VersionDriftRowsRow{
		row(1, "alone", "1.0.0", 0), row(2, "alone", "1.0.0", 0), // one version only: dropped
		row(1, "wide", "10.0.0", 0), row(2, "wide", "2.1.0", 0), row(3, "wide", "9.0.0", 0),
		row(1, "many", "1.0.0", 0), row(2, "many", "1.1.0", 0), row(3, "many", "1.2.0", 0), row(4, "many", "1.2.0", 0),
		row(1, "few", "1.0.0", 0), row(2, "few", "1.1.0", 0),
		row(1, "vuln", "1.0.0", 2), row(2, "vuln", "1.0.1", 0),
	}
	got := groupDrift(rows, 200)
	names := []string{}
	for _, p := range got {
		names = append(names, p.Name)
	}
	want := []string{"vuln", "wide", "many", "few"}
	if len(names) != len(want) {
		t.Fatalf("names = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("names = %v, want %v", names, want)
		}
	}
	wide := got[1]
	if wide.Spread != 8 || wide.Versions[0].Version != "2.1.0" || wide.Versions[2].Version != "10.0.0" {
		t.Errorf("wide = %+v, want spread 8 and semver order", wide)
	}
	many := got[2]
	if many.Projects != 4 || len(many.Versions[2].Projects) != 2 {
		t.Errorf("many = %+v, want 4 projects and 2 on 1.2.0", many)
	}
	if !got[0].Vulnerable || got[0].Versions[0].OpenVulns != 2 || got[0].Versions[1].OpenVulns != 0 {
		t.Errorf("vuln = %+v", got[0])
	}
	if len(groupDrift(rows, 2)) != 2 {
		t.Error("limit not applied")
	}
}
