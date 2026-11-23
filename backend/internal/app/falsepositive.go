package app

import (
	"context"
	"fmt"
	"slices"
	"strconv"

	"limier/internal/db/dbq"
	"limier/internal/scanners/ignore"
	"limier/internal/scanners/imports"
	"limier/internal/scanners/source"
)

// fpDetail is the detail a false positive is matched on. A per-file count (console-log, ts-any)
// changes with the code, so it is left out and the mark covers the rule in the whole file.
func fpDetail(detail string) string {
	if _, err := strconv.Atoi(detail); err == nil {
		return ""
	}
	return detail
}

// SetFalsePositive marks (or, with on=false, unmarks) a code finding of the project as a false
// positive, then rescans the code so the results and ratings follow.
func (a *App) SetFalsePositive(ctx context.Context, projectID int64, rule, file, detail string, on bool) error {
	if rule == "" || len(rule) > 100 || len(file) > 1000 || len(detail) > 2000 {
		return fmt.Errorf("%w: rule, file or detail", ErrInvalid)
	}
	p, err := a.rootProject(ctx, projectID)
	if err != nil {
		return err
	}
	if on {
		err = a.q.AddCodeFalsePositive(ctx, dbq.AddCodeFalsePositiveParams{ProjectID: p.ID, Rule: rule, File: file, Detail: fpDetail(detail)})
	} else {
		err = a.q.DeleteCodeFalsePositive(ctx, dbq.DeleteCodeFalsePositiveParams{ProjectID: p.ID, Rule: rule, File: file, Detail: fpDetail(detail)})
	}
	if err != nil {
		return err
	}
	a.enqueueQuiet(ctx, p.ID, "code", "manual")
	return nil
}

// dropFalsePositives moves the findings marked as false positives from d to d.Ignored.
func dropFalsePositives(d *codeDetails, marks []dbq.CodeFalsePositive) {
	type key struct{ rule, file, detail string }
	set := make(map[key]bool, len(marks))
	for _, m := range marks {
		set[key{m.Rule, m.File, m.Detail}] = true
	}
	if len(set) == 0 {
		return
	}
	hide := func(rule, file string, line int, detail string) bool {
		k := key{rule, file, fpDetail(detail)}
		if set[k] {
			d.Ignored = append(d.Ignored, ignore.Ignored{Rule: rule, File: file, Line: line, Detail: k.detail, FalsePositive: true})
		}
		return set[k]
	}
	for _, list := range []*[]source.Issue{&d.Secrets, &d.Flaws, &d.Smells, &d.UnusedExports} {
		*list = slices.DeleteFunc(*list, func(is source.Issue) bool { return hide(is.Rule, is.File, is.Line, is.Detail) })
	}
	d.DeadFiles = slices.DeleteFunc(d.DeadFiles, func(f string) bool { return hide(imports.RuleDeadFile, f, 0, "") })
	d.UnusedDependencies = slices.DeleteFunc(d.UnusedDependencies, func(n string) bool { return hide(imports.RuleUnusedDep, "", 0, n) })
}
