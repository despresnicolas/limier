package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"limier/internal/db/dbq"
	"limier/internal/scanners"
)

// Projects are directories under LOCAL_REPOS_ROOT.

var ErrLocalDisabled = fmt.Errorf("%w: local projects are disabled (LOCAL_REPOS_ROOT is not set)", ErrInvalid)

const (
	sourceMount   = "/source"
	maxLocalFiles = 200_000
)

// resolveLocal validates a path relative to LOCAL_REPOS_ROOT and returns the cleaned relative path.
// Symlinks are resolved so that a link cannot escape the root.
func (a *App) resolveLocal(rel string) (string, error) {
	if a.cfg.LocalReposRoot == "" {
		return "", ErrLocalDisabled
	}
	root, err := filepath.EvalSymlinks(a.cfg.LocalReposRoot)
	if err != nil {
		return "", fmt.Errorf("LOCAL_REPOS_ROOT: %w", err)
	}
	// Accept either a path relative to the root or an absolute path inside it.
	candidate := rel
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(root, filepath.Clean(string(filepath.Separator)+rel))
	}
	real, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", fmt.Errorf("%w: directory not found", ErrInvalid)
	}
	out, err := filepath.Rel(root, real)
	if err != nil || out == ".." || strings.HasPrefix(out, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: path is outside LOCAL_REPOS_ROOT", ErrInvalid)
	}
	if st, err := os.Stat(real); err != nil || !st.IsDir() {
		return "", fmt.Errorf("%w: not a directory", ErrInvalid)
	}
	if strings.ContainsAny(out, ":,") {
		return "", fmt.Errorf("%w: unsupported characters in path", ErrInvalid)
	}
	// Hidden folders (.ssh, .config...) are never browsed nor registered, even when the root is $HOME.
	for _, part := range strings.Split(filepath.ToSlash(out), "/") {
		if strings.HasPrefix(part, ".") && part != "." {
			return "", fmt.Errorf("%w: hidden folders are not allowed", ErrInvalid)
		}
	}
	if out == "." {
		return "", nil
	}
	return filepath.ToSlash(out), nil
}

// detectLocal runs the Node.js detection on a local directory.
func (a *App) detectLocal(rel string) (scanners.Detection, error) {
	dir := filepath.Join(a.cfg.LocalReposRoot, filepath.FromSlash(rel))
	var tree []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entries are skipped
		}
		if d.IsDir() && (d.Name() == "node_modules" || d.Name() == ".git") {
			return filepath.SkipDir
		}
		if d.Type().IsRegular() {
			if len(tree) >= maxLocalFiles {
				return errors.New("too many files")
			}
			r, _ := filepath.Rel(dir, p)
			tree = append(tree, filepath.ToSlash(r))
		}
		return nil
	})
	if err != nil {
		return scanners.Detection{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return scanners.Detection{}, err
	}
	read := func(p string) ([]byte, error) {
		real, err := filepath.EvalSymlinks(filepath.Join(dir, filepath.FromSlash(path.Clean("/"+p))))
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fs.ErrNotExist
		}
		if err != nil {
			return nil, err
		}
		// A symlinked manifest must not make us read files outside the repository.
		if r, err := filepath.Rel(realDir, real); err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
			return nil, fs.ErrNotExist
		}
		return os.ReadFile(real)
	}
	return scanners.DetectFromFiles(tree, read)
}

// RegisterLocalProject registers (or refreshes) a local directory as a project and queues its first scans.
func (a *App) RegisterLocalProject(ctx context.Context, rawPath, name string) (dbq.Project, error) {
	rel, err := a.resolveLocal(rawPath)
	if err != nil {
		return dbq.Project{}, err
	}
	det, err := a.detectLocal(rel)
	if err != nil {
		return dbq.Project{}, err
	}
	if !det.NodeProject {
		return dbq.Project{}, fmt.Errorf("%w: %s", ErrInvalid, det.IgnoreReason)
	}
	if name = strings.TrimSpace(name); name == "" {
		name = "local/" + rel
	}
	root, err := a.q.UpsertLocalProject(ctx, dbq.UpsertLocalProjectParams{LocalPath: rel, Path: name, Subdir: "", PackageManager: det.PackageManager})
	if err != nil {
		return root, err
	}
	keep := make([]string, 0, len(det.Workspaces))
	for _, ws := range det.Workspaces {
		keep = append(keep, ws.Dir)
		if _, err := a.q.UpsertLocalProject(ctx, dbq.UpsertLocalProjectParams{
			LocalPath: rel, ParentID: &root.ID, Path: name + "/" + ws.Dir, Subdir: ws.Dir, PackageManager: det.PackageManager,
		}); err != nil {
			return root, err
		}
	}
	if err := a.q.DeleteStaleWorkspaces(ctx, dbq.DeleteStaleWorkspacesParams{ParentID: &root.ID, Keep: keep}); err != nil {
		return root, err
	}
	a.enqueueQuiet(ctx, root.ID, "deps", "manual")
	a.enqueueQuiet(ctx, root.ID, "code", "manual")
	return a.q.GetProject(ctx, root.ID)
}

// LocalDir is a sub-folder shown by the folder browser.
type LocalDir struct {
	Name       string `json:"name"`
	Path       string `json:"path"` // relative to LOCAL_REPOS_ROOT
	Node       bool   `json:"node"` // holds a package.json: can be analysed
	Git        bool   `json:"git"`  // holds a .git directory: fixes can become branches
	Registered bool   `json:"registered"`
}

// LocalBrowse is the content of one folder under LOCAL_REPOS_ROOT.
type LocalBrowse struct {
	Root string `json:"root"` // absolute root, for display
	Path string `json:"path"` // "" for the root
	Node bool   `json:"node"`
	Git  bool   `json:"git"`
	// Registered tells whether the folder itself is already a project.
	Registered bool       `json:"registered"`
	Dirs       []LocalDir `json:"dirs"`
	Trunc      bool       `json:"truncated"`
}

const maxBrowseEntries = 500

// BrowseLocal lists the visible sub-folders of rel so that an admin can pick folders to analyse.
func (a *App) BrowseLocal(ctx context.Context, rel string) (LocalBrowse, error) {
	b, err := a.listLocalDir(rel)
	if err != nil {
		return b, err
	}
	paths, err := a.q.ListLocalPaths(ctx)
	if err != nil {
		return b, err
	}
	registered := map[string]bool{}
	for _, p := range paths {
		registered[p] = true
	}
	b.Registered = registered[b.Path]
	for i := range b.Dirs {
		b.Dirs[i].Registered = registered[b.Dirs[i].Path]
	}
	return b, nil
}

func (a *App) listLocalDir(rel string) (LocalBrowse, error) {
	clean, err := a.resolveLocal(rel)
	if err != nil {
		return LocalBrowse{}, err
	}
	dir := filepath.Join(a.cfg.LocalReposRoot, filepath.FromSlash(clean))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return LocalBrowse{}, fmt.Errorf("%w: cannot read folder: %v", ErrInvalid, err)
	}
	b := LocalBrowse{Root: a.cfg.LocalReposRoot, Path: clean, Node: isFile(filepath.Join(dir, "package.json")), Git: isDir(filepath.Join(dir, ".git")), Dirs: []LocalDir{}}
	for _, e := range entries {
		// Symlinks are skipped: a link could point outside the root.
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") || e.Name() == "node_modules" || strings.ContainsAny(e.Name(), ":,") {
			continue
		}
		if len(b.Dirs) == maxBrowseEntries {
			b.Trunc = true
			break
		}
		child := filepath.Join(dir, e.Name())
		b.Dirs = append(b.Dirs, LocalDir{
			Name: e.Name(), Path: path.Join(clean, e.Name()),
			Node: isFile(filepath.Join(child, "package.json")), Git: isDir(filepath.Join(child, ".git")),
		})
	}
	sort.Slice(b.Dirs, func(i, j int) bool { return strings.ToLower(b.Dirs[i].Name) < strings.ToLower(b.Dirs[j].Name) })
	return b, nil
}

func isFile(p string) bool { st, err := os.Lstat(p); return err == nil && st.Mode().IsRegular() }
func isDir(p string) bool  { st, err := os.Lstat(p); return err == nil && st.IsDir() }

// DeleteProject removes a project and its history, never its folder.
func (a *App) DeleteProject(ctx context.Context, id int64) error {
	p, err := a.q.GetProject(ctx, id)
	if err != nil {
		return err
	}
	if p.ParentID != nil {
		return fmt.Errorf("%w: workspaces are deleted with their root project", ErrInvalid)
	}
	_, err = a.q.DeleteProject(ctx, id)
	return err
}

// localUserEmail identifies the single user of the desktop app, recorded on fix decisions.
// Keeps the old app name: existing fix decisions point to the user row with this email.
const localUserEmail = "local@seckit.local"

// LocalUserID returns the local user, creating it on first start.
func (a *App) LocalUserID(ctx context.Context) (int64, error) {
	u, err := a.q.CreateUser(ctx, dbq.CreateUserParams{Email: localUserEmail, Name: "Local"})
	return u.ID, err
}
