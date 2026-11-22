package app

import (
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/riverqueue/river"

	"limier/internal/db/dbq"
	"limier/internal/scanners/churn"
	"limier/internal/scanners/coverage"
	"limier/internal/scanners/dupes"
	"limier/internal/scanners/ignore"
	"limier/internal/scanners/imports"
	"limier/internal/scanners/nodeeol"
	"limier/internal/scanners/quality"
	"limier/internal/scanners/sast"
	"limier/internal/scanners/secrets"
	"limier/internal/scanners/source"
)

const (
	maxGraphNodes = 5000
	// maxIssues keeps details small on huge projects.
	// shortcut: the Code tab shows the first 300 issues per category, store them in a table if users need paging.
	maxIssues = 300
)

// codeDetails is the JSON shape of code_metrics.details read by the Code tab.
type codeDetails struct {
	Secrets            []source.Issue        `json:"secrets"`
	Flaws              []source.Issue        `json:"flaws"`
	Smells             []source.Issue        `json:"smells"`
	QuickWins          []string              `json:"quick_wins"`
	Hotspots           []quality.Function    `json:"hotspots"`
	HotFiles           []quality.FileHotspot `json:"hot_files"`
	Functions          int                   `json:"functions"`
	AvgComplexity      float64               `json:"avg_complexity"`
	Duplication        dupes.Report          `json:"duplication"`
	Cycles             [][]string            `json:"cycles"`
	DeadFiles          []string              `json:"dead_files"`
	UnusedExports      []source.Issue        `json:"unused_exports"`
	UnusedDependencies []string              `json:"unused_dependencies"`
	Coverage           coverage.Report       `json:"coverage"`
	Ignored            []ignore.Ignored      `json:"ignored,omitempty"` // findings hidden by limier-ignore comments
	Truncated          bool                  `json:"truncated,omitempty"`
}

// workScanCode analyses the project folder in Go (SPECS F3): nothing from the project is run.
func (a *App) workScanCode(ctx context.Context, job *river.Job[ScanCodeArgs]) error {
	return runScan(ctx, a, job, job.Args.ScanID, func(ctx context.Context, scan dbq.Scan) error {
		p, err := a.q.GetProject(ctx, scan.ProjectID)
		if err != nil {
			return err
		}
		rel, err := a.resolveLocal(p.LocalPath)
		if err != nil {
			return permanent("local directory unavailable: %v", err)
		}
		dir := filepath.Join(a.cfg.LocalReposRoot, rel)
		if commit := headCommit(dir); commit != "" {
			_ = a.q.SetScanCommit(ctx, dbq.SetScanCommitParams{ID: scan.ID, CommitSha: commit})
		}
		files, err := source.Walk(dir)
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}

		langs, loc := source.Count(files)
		graph := imports.Analyze(files)
		qual := quality.Analyze(files)
		// shortcut: 2000 commits at most keeps big histories fast, raise it if 12 months need more.
		if counts, err := churn.Count(dir, time.Now().AddDate(-1, 0, 0), 2000); err == nil {
			qual.AddChurn(counts)
		}
		// limier-ignore comments (SPECS F3) drop false positives here, before anything counts or rates them.
		// Never node.eol, clones or dependency vulnerabilities.
		secretIssues, sastIssues := secrets.Analyze(files), sast.Analyze(files)
		ignored := ignore.Filter(files, &secretIssues, &sastIssues, &qual.Issues)
		d := codeDetails{
			Secrets:            secretIssues,
			Flaws:              append(nodeeol.Analyze(dir, time.Now()), sastIssues...), // EOL first: the issue cap never hides it
			Smells:             qual.Issues,
			Ignored:            ignored,
			Hotspots:           qual.Hotspots,
			HotFiles:           qual.HotFiles,
			Functions:          qual.Functions,
			AvgComplexity:      qual.AvgComplexity,
			Duplication:        dupes.Analyze(files),
			Cycles:             graph.Cycles,
			DeadFiles:          graph.DeadFiles,
			UnusedExports:      graph.UnusedExports,
			UnusedDependencies: graph.UnusedDeps,
			Coverage:           coverage.Analyze(dir, files, graph),
		}
		if p.LastCodeScanID != nil {
			if prev, err := a.q.GetCodeMetrics(ctx, *p.LastCodeScanID); err == nil {
				var old codeDetails
				if json.Unmarshal(prev.Details, &old) == nil {
					markNew(old.Secrets, d.Secrets)
					markNew(old.Flaws, d.Flaws)
					markNew(old.Smells, d.Smells)
					markNew(old.UnusedExports, d.UnusedExports)
				}
			}
		}
		for id := range quality.QuickWins {
			d.QuickWins = append(d.QuickWins, id)
		}
		slices.Sort(d.QuickWins)
		m := dbq.InsertCodeMetricsParams{
			ScanID: scan.ID, Loc: loc,
			UnusedDeps:   int32(len(d.UnusedDependencies)),
			Cycles:       int32(len(d.Cycles)),
			Secrets:      int32(len(d.Secrets)),
			SastFindings: int32(len(d.Flaws)),
			DeadFiles:    int32(len(d.DeadFiles)),
			// Counted before truncation so the history stays exact.
			ComplexFunctions: int32(countRule(d.Smells, "quality.complex-function")),
			DuplicatedLines:  int32(d.Duplication.DuplicatedLines),
		}
		debt := debtMinutes(d)
		m.DebtMinutes = int32(debt)
		m.SecurityRating, m.ReliabilityRating, m.MaintainabilityRating = codeRatings(d, loc, debt)
		for _, list := range []*[]source.Issue{&d.Secrets, &d.Flaws, &d.Smells, &d.UnusedExports} {
			if len(*list) > maxIssues {
				*list, d.Truncated = (*list)[:maxIssues], true
			}
		}
		if len(d.Ignored) > maxIssues {
			d.Ignored, d.Truncated = d.Ignored[:maxIssues], true
		}
		if m.Languages, err = json.Marshal(langs); err != nil {
			return err
		}
		if m.Details, err = json.Marshal(d); err != nil {
			return err
		}
		if err := a.q.InsertCodeMetrics(ctx, m); err != nil {
			return err
		}
		if err := a.q.UpsertCodeGraph(ctx, dbq.UpsertCodeGraphParams{ScanID: scan.ID, Graph: graphJSON(graph)}); err != nil {
			return err
		}
		if err := a.q.SetProjectLastCodeScan(ctx, dbq.SetProjectLastCodeScanParams{ID: p.ID, LastCodeScanID: &scan.ID}); err != nil {
			return err
		}
		// A new import graph changes reachability of the current findings.
		p.LastCodeScanID = &scan.ID
		return a.recomputeProject(ctx, p)
	})
}

// headCommit returns the HEAD commit of the repository containing dir, "" outside git.
func headCommit(dir string) string {
	repo, err := git.PlainOpenWithOptions(dir, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return ""
	}
	ref, err := repo.Head()
	if err != nil {
		return ""
	}
	return ref.Hash().String()
}

// markNew flags the issues of cur missing from prev. Lines shift between scans, so an issue is
// identified by rule, file and detail; repeats count, so a third identical issue in a file is new.
// shortcut: prev is capped at maxIssues, so on huge projects issues past the cap may show as new; store issues in a table to fix.
func markNew(prev, cur []source.Issue) {
	key := func(i source.Issue) string { return i.Rule + "\x00" + i.File + "\x00" + i.Detail }
	seen := map[string]int{}
	for _, i := range prev {
		seen[key(i)]++
	}
	for k := range cur {
		if n := seen[key(cur[k])]; n > 0 {
			seen[key(cur[k])] = n - 1
		} else {
			cur[k].New = true
		}
	}
}

func countRule(issues []source.Issue, rule string) int {
	n := 0
	for _, i := range issues {
		if i.Rule == rule {
			n++
		}
	}
	return n
}

// graphJSON keeps the graph displayable and records imported packages for reachability and fix effort.
func graphJSON(r imports.Report) []byte {
	imported := make([]string, 0, len(r.ImportedPackages))
	for name := range r.ImportedPackages {
		imported = append(imported, name)
	}
	slices.Sort(imported)
	nodes, edges, truncated := r.Nodes, r.Edges, false
	if len(nodes) > maxGraphNodes {
		truncated = true
		nodes = nodes[:maxGraphNodes]
		keep := map[string]bool{}
		for _, n := range nodes {
			keep[n.ID] = true
		}
		edges = slices.DeleteFunc(slices.Clone(edges), func(e imports.Edge) bool { return !keep[e.From] || !keep[e.To] })
	}
	type node struct {
		ID       string `json:"id"`
		External bool   `json:"external"`
		Package  string `json:"package,omitempty"`
	}
	type edge struct {
		From     string `json:"from"`
		To       string `json:"to"`
		Circular bool   `json:"circular,omitempty"`
	}
	usage := r.PackageUsage
	if usage == nil {
		usage = map[string]int{}
	}
	out := struct {
		Nodes            []node   `json:"nodes"`
		Edges            []edge   `json:"edges"`
		ImportedPackages []string `json:"imported_packages"`
		// PackageUsage counts the local files importing each package (fix effort).
		PackageUsage map[string]int `json:"package_usage"`
		Truncated    bool           `json:"truncated"`
	}{Nodes: []node{}, Edges: []edge{}, ImportedPackages: imported, PackageUsage: usage, Truncated: truncated}
	for _, n := range nodes {
		out.Nodes = append(out.Nodes, node{n.ID, n.External, n.Package})
	}
	for _, e := range edges {
		out.Edges = append(out.Edges, edge{e.From, e.To, e.Circular})
	}
	b, _ := json.Marshal(out)
	return b
}
