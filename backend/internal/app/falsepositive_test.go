package app

import (
	"testing"

	"limier/internal/db/dbq"
	"limier/internal/scanners/source"
)

func TestDropFalsePositives(t *testing.T) {
	d := codeDetails{
		Secrets:            []source.Issue{{Rule: "secret.github-token", File: "a.ts", Line: 3, Detail: "ghp_…abcd"}, {Rule: "secret.github-token", File: "b.ts", Line: 1, Detail: "ghp_…abcd"}},
		Smells:             []source.Issue{{Rule: "quality.console-log", File: "c.ts", Line: 9, Detail: "4"}},
		DeadFiles:          []string{"old.ts", "keep.ts"},
		UnusedDependencies: []string{"lodash", "react"},
	}
	dropFalsePositives(&d, []dbq.CodeFalsePositive{
		{Rule: "secret.github-token", File: "a.ts", Detail: "ghp_…abcd"},
		{Rule: "quality.console-log", File: "c.ts"}, // a count detail is stored as ""
		{Rule: "imports.dead-file", File: "old.ts"},
		{Rule: "imports.unused-dep", Detail: "lodash"},
	})
	if len(d.Secrets) != 1 || d.Secrets[0].File != "b.ts" {
		t.Errorf("secrets = %+v", d.Secrets)
	}
	if len(d.Smells) != 0 || len(d.DeadFiles) != 1 || d.DeadFiles[0] != "keep.ts" || len(d.UnusedDependencies) != 1 || d.UnusedDependencies[0] != "react" {
		t.Errorf("smells %v dead %v deps %v", d.Smells, d.DeadFiles, d.UnusedDependencies)
	}
	if len(d.Ignored) != 4 || !d.Ignored[0].FalsePositive || d.Ignored[0].Line != 3 {
		t.Errorf("ignored = %+v", d.Ignored)
	}
}
