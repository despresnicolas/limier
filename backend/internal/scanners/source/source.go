// Package source reads a project's files once for every code analyser (SPECS F3).
// It never executes anything from the project.
package source

import (
	"bytes"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
)

// Severity of an Issue.
const (
	High   = "high"
	Medium = "medium"
	Low    = "low"
	Info   = "info"
)

// Issue is one finding of a code analyser, shown as file:line in the Code tab.
// Rule is a stable id the UI translates; Detail is free data (never a secret in clear).
type Issue struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	File     string `json:"file"`
	Line     int    `json:"line,omitempty"`
	EndLine  int    `json:"end_line,omitempty"`
	Detail   string `json:"detail,omitempty"`
	New      bool   `json:"new,omitempty"` // absent from the previous code scan
}

// File is a project text file. Path is slash-separated and relative to the root.
// Code is Src with comments and string/regex contents blanked to spaces (newlines and
// offsets kept), so pattern rules only match real code; it is nil for non-code files.
type File struct {
	Path string
	Lang string // "JavaScript", "TypeScript", "Svelte", "Vue" for code; "JSON", "YAML", "Env"… otherwise
	Src  []byte
	Code []byte
}

// IsCode reports whether the file is JS/TS (or a Svelte/Vue component).
func (f File) IsCode() bool { return f.Code != nil }

// LineAt returns the 1-based line of a byte offset in Src.
func (f File) LineAt(off int) int { return LineAt(f.Src, off) }

// LineAt returns the 1-based line of a byte offset.
func LineAt(b []byte, off int) int {
	if off > len(b) {
		off = len(b)
	}
	return bytes.Count(b[:off], []byte{'\n'}) + 1
}

// MaxFileSize skips minified bundles and generated blobs.
const MaxFileSize = 1 << 20

var skipDirs = map[string]bool{
	"node_modules": true, ".git": true, "dist": true, "build": true, "out": true, "coverage": true,
	".next": true, ".nuxt": true, ".svelte-kit": true, ".output": true, ".turbo": true, ".cache": true,
	".vercel": true, ".netlify": true, "vendor": true, "bower_components": true, ".yarn": true, ".pnpm-store": true,
}

var codeLangs = map[string]string{
	".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".jsx": "JavaScript",
	".ts": "TypeScript", ".mts": "TypeScript", ".cts": "TypeScript", ".tsx": "TypeScript",
	".svelte": "Svelte", ".vue": "Vue",
}

var textLangs = map[string]string{
	".json": "JSON", ".yml": "YAML", ".yaml": "YAML", ".toml": "TOML", ".ini": "INI", ".properties": "INI",
	".xml": "XML", ".html": "HTML", ".htm": "HTML", ".css": "CSS", ".scss": "CSS", ".md": "Markdown",
	".sh": "Shell", ".bash": "Shell", ".zsh": "Shell", ".py": "Python", ".rb": "Ruby", ".php": "PHP",
	".go": "Go", ".java": "Java", ".kt": "Kotlin", ".cs": "C#", ".sql": "SQL", ".tf": "Terraform",
	".pem": "Key", ".key": "Key", ".txt": "Text", ".conf": "INI", ".cfg": "INI",
}

// Lang returns the language of a path, "" when the file is not read.
func Lang(p string) string {
	base := path.Base(p)
	ext := strings.ToLower(path.Ext(base))
	if strings.HasSuffix(base, ".min.js") || strings.HasSuffix(base, ".d.ts") {
		return ""
	}
	if l, ok := codeLangs[ext]; ok {
		return l
	}
	switch {
	case base == ".env" || strings.HasPrefix(base, ".env."):
		return "Env"
	case base == ".npmrc" || base == ".yarnrc" || base == ".yarnrc.yml":
		return "Env"
	case base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile."):
		return "Dockerfile"
	case base == "id_rsa" || base == "id_ecdsa" || base == "id_ed25519":
		return "Key"
	}
	return textLangs[ext]
}

// IsCodeLang reports whether Lang is analysed as JS/TS.
func IsCodeLang(l string) bool {
	return l == "JavaScript" || l == "TypeScript" || l == "Svelte" || l == "Vue"
}

// Walk reads the text files under root, skipping dependencies, build output, hidden
// folders (except .github), gitignored paths, symlinks, binaries and files over MaxFileSize.
// Files come back sorted by path.
func Walk(root string) ([]File, error) {
	var files []File
	var patterns []gitignore.Pattern
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == root {
				return err
			}
			return nil // unreadable entry: skip it, keep scanning
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		parts := strings.Split(rel, "/")
		if d.IsDir() {
			if rel == "." {
				patterns = append(patterns, readIgnore(p, nil)...)
				return nil
			}
			name := d.Name()
			if skipDirs[name] || (strings.HasPrefix(name, ".") && name != ".github") ||
				gitignore.NewMatcher(patterns).Match(parts, true) {
				return filepath.SkipDir
			}
			patterns = append(patterns, readIgnore(p, parts)...)
			return nil
		}
		if !d.Type().IsRegular() {
			return nil // symlinks and devices: never followed (F1.5)
		}
		lang := Lang(rel)
		if lang == "" || gitignore.NewMatcher(patterns).Match(parts, false) {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > MaxFileSize {
			return nil
		}
		src, err := os.ReadFile(p)
		if err != nil || bytes.IndexByte(src[:min(len(src), 8000)], 0) >= 0 {
			return nil
		}
		f := File{Path: rel, Lang: lang, Src: src}
		if IsCodeLang(lang) {
			f.Code = Strip(src, lang)
		}
		files = append(files, f)
		return nil
	})
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, err
}

// readIgnore reads dir/.gitignore; domain is the dir relative to the root.
func readIgnore(dir string, domain []string) []gitignore.Pattern {
	b, err := os.ReadFile(filepath.Join(dir, ".gitignore"))
	if err != nil {
		return nil
	}
	var ps []gitignore.Pattern
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ps = append(ps, gitignore.ParsePattern(line, domain))
	}
	return ps
}
