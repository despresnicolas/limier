// Package churn counts how often each file changed in the git history (SPECS F3.6). It only
// reads the repository objects with go-git: no git binary, no hook, no write.
package churn

import (
	"errors"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// Count returns, per file path relative to dir, the number of commits that changed it since
// `since`. It walks the first-parent history from HEAD and skips merge commits. dir may be a
// subfolder of the repository (a workspace package): files outside it are ignored.
// Outside git, in an empty repository or a bare one, it returns an empty map and no error.
// Renames are not followed: a renamed file starts again from zero under its new name.
// It stops after maxCommits non-merge commits.
func Count(dir string, since time.Time, maxCommits int) (map[string]int, error) {
	out := map[string]int{}
	repo, err := git.PlainOpenWithOptions(dir, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return out, nil
	}
	wt, err := repo.Worktree()
	if err != nil {
		return out, nil
	}
	prefix, err := relPrefix(wt.Filesystem.Root(), dir)
	if err != nil {
		return out, nil
	}
	head, err := repo.Head()
	if err != nil {
		return out, nil
	}
	c, err := repo.CommitObject(head.Hash())
	if err != nil {
		return out, nil
	}
	for n := 0; n < maxCommits && !c.Committer.When.Before(since); {
		var parent *object.Commit
		if c.NumParents() > 0 {
			if parent, err = c.Parent(0); err != nil {
				return out, err
			}
		}
		if c.NumParents() <= 1 {
			n++
			if err := countCommit(c, parent, prefix, out); err != nil {
				return out, err
			}
		}
		if parent == nil {
			break
		}
		c = parent
	}
	return out, nil
}

// countCommit adds one to every file under prefix that c changed compared with parent (nil: root commit).
func countCommit(c, parent *object.Commit, prefix string, out map[string]int) error {
	tree, err := c.Tree()
	if err != nil {
		return err
	}
	var from *object.Tree
	if parent != nil {
		if from, err = parent.Tree(); err != nil {
			return err
		}
	}
	changes, err := object.DiffTree(from, tree)
	if err != nil {
		return err
	}
	for _, ch := range changes {
		name := ch.To.Name
		if name == "" { // deletion
			name = ch.From.Name
		}
		if rel, ok := strings.CutPrefix(name, prefix); ok {
			out[rel]++
		}
	}
	return nil
}

// relPrefix returns dir relative to the repository root as a slash path ending in "/", "" at the root.
func relPrefix(root, dir string) (string, error) {
	var err error
	if root, err = filepath.EvalSymlinks(root); err != nil {
		return "", err
	}
	if dir, err = filepath.EvalSymlinks(dir); err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return "", err
	}
	if rel == "." {
		return "", nil
	}
	if strings.HasPrefix(rel, "..") {
		return "", errors.New("directory outside the repository")
	}
	return filepath.ToSlash(rel) + "/", nil
}
