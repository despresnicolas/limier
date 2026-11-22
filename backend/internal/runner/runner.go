// Package runner executes scan pipelines in ephemeral, hardened containers.
//
// A Pipeline is a list of sequential Steps sharing a work directory mounted at
// /work. After the last step, the files listed in Pipeline.Outputs are
// collected back into the Result. The backend talks to the Docker Engine API
// over HTTP, without the moby SDK.
//
// Steps run untrusted code (dependency tooling, scanners operating on
// untrusted repositories), so every container is non-root by default, has a
// read-only root filesystem, drops all capabilities, cannot gain new
// privileges and has no network unless Step.Network is set.
//
// Step.Env may carry secrets: values are never logged nor included in errors.
package runner

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Default values applied to Steps and Pipelines.
const (
	DefaultUser           = "65532:65532"
	DefaultWorkingDir     = "/work"
	DefaultMaxOutputBytes = 64 << 20 // 64 MiB

	// WorkDir is the mount point of the shared work volume in every step.
	WorkDir = "/work"

	// MaxLogBytes is the maximum size kept for each of StepResult.Stdout and
	// StepResult.Stderr.
	MaxLogBytes = 1 << 20 // 1 MiB

	stderrTailBytes = 2 << 10 // 2 KiB kept in StepError.Stderr
	cleanupTimeout  = 60 * time.Second

	// Labels set on every resource created by a runner.
	LabelPipeline = "limier.io/pipeline"
	LabelNetwork  = "limier.io/network"
	LabelStep     = "limier.io/step"
)

// Step is one command executed in its own container.
type Step struct {
	Name  string
	Image string
	// Cmd is the full argv in exec form (no shell implied). When non-empty it
	// replaces both the image ENTRYPOINT and CMD. When empty, the image
	// defaults are used.
	Cmd []string
	// Env may contain secrets (tokens): values are never logged.
	Env map[string]string
	// Network enables network access. When false the step has no network at
	// all (Docker NetworkMode "none").
	Network bool
	// AllowFailure makes a non-zero exit code non-fatal for the pipeline.
	AllowFailure bool
	// Timeout bounds the step duration; 0 means only the pipeline deadline
	// (ctx) applies. A timeout always aborts the pipeline, even with
	// AllowFailure.
	Timeout time.Duration
	// User is "uid:gid" (default "65532:65532").
	User string
	// WorkingDir defaults to /work.
	WorkingDir string
	// Mounts bind host directories into the step (Docker runner only).
	Mounts []Mount
}

// Mount is a host directory exposed to a step, read-only unless Writable is set.
// Only steps that run trusted commands (never repository tooling) get a writable mount.
type Mount struct {
	Source   string // absolute path as seen by the Docker daemon
	Target   string // absolute path in the container, outside /work
	Writable bool
}

// Pipeline is an ordered list of steps sharing the /work directory.
type Pipeline struct {
	// ID is unique and used to name volumes and pods (sanitized to DNS-1123).
	ID    string
	Steps []Step
	// Outputs are paths relative to /work collected after all steps. Missing
	// files are simply absent from Result.Files. A directory is collected
	// recursively (regular files only). Absolute paths and paths containing
	// ".." are rejected.
	Outputs []string
	// MaxOutputBytes bounds the total size of collected files (default 64 MiB).
	MaxOutputBytes int64
}

// StepResult describes the execution of one step.
type StepResult struct {
	Name     string
	ExitCode int
	// Stdout and Stderr are truncated to MaxLogBytes each.
	Stdout, Stderr []byte
	Duration       time.Duration
}

// Result is the outcome of a pipeline run. It may be partial when Run returns
// an error.
type Result struct {
	Steps []StepResult
	// Files maps output paths (relative to /work, slash separated) to their
	// content.
	Files map[string][]byte
}

// Runner executes pipelines.
//
// Run returns an error (and a partial Result) when a step without
// AllowFailure exits non-zero (*StepError), on timeout or ctx cancellation
// (the error wraps context.DeadlineExceeded / context.Canceled), or on
// infrastructure failure. Created resources are always cleaned up, even when
// ctx is cancelled.
type Runner interface {
	Run(ctx context.Context, p Pipeline) (*Result, error)
}

// StepError reports a step that exited with a non-zero code without
// AllowFailure.
type StepError struct {
	Step     string
	ExitCode int
	// Stderr holds the last 2 KiB of the step's stderr.
	Stderr string
}

func (e *StepError) Error() string {
	return fmt.Sprintf("runner: step %q exited with code %d", e.Step, e.ExitCode)
}

// ErrOutputTooLarge is returned (wrapped) when collected outputs exceed
// Pipeline.MaxOutputBytes.
var ErrOutputTooLarge = errors.New("runner: collected outputs exceed MaxOutputBytes")

// ErrInvalidPipeline is returned (wrapped) when a pipeline fails validation.
var ErrInvalidPipeline = errors.New("runner: invalid pipeline")

var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// normalize validates p and returns a copy with defaults applied.
func normalize(p Pipeline) (Pipeline, error) {
	if len(p.Steps) == 0 {
		return p, fmt.Errorf("%w: no steps", ErrInvalidPipeline)
	}
	out := p
	out.Steps = make([]Step, len(p.Steps))
	for i, s := range p.Steps {
		if s.Name == "" {
			s.Name = fmt.Sprintf("step-%d", i)
		}
		if s.Image == "" {
			return p, fmt.Errorf("%w: step %q has no image", ErrInvalidPipeline, s.Name)
		}
		if s.User == "" {
			s.User = DefaultUser
		}
		if s.WorkingDir == "" {
			s.WorkingDir = DefaultWorkingDir
		}
		if s.Timeout < 0 {
			return p, fmt.Errorf("%w: step %q has a negative timeout", ErrInvalidPipeline, s.Name)
		}
		for _, m := range s.Mounts {
			if !path.IsAbs(m.Source) || !path.IsAbs(m.Target) || path.Clean(m.Target) == "/" ||
				path.Clean(m.Target) == WorkDir || strings.HasPrefix(path.Clean(m.Target)+"/", WorkDir+"/") || strings.ContainsAny(m.Source+m.Target, ":,") {
				return p, fmt.Errorf("%w: step %q has an invalid mount %q -> %q", ErrInvalidPipeline, s.Name, m.Source, m.Target)
			}
		}
		for k := range s.Env {
			if !envNameRe.MatchString(k) {
				return p, fmt.Errorf("%w: step %q has an invalid env var name %q", ErrInvalidPipeline, s.Name, k)
			}
		}
		out.Steps[i] = s
	}
	out.Outputs = make([]string, 0, len(p.Outputs))
	seen := map[string]bool{}
	for _, o := range p.Outputs {
		c, err := cleanOutputPath(o)
		if err != nil {
			return p, err
		}
		if !seen[c] {
			seen[c] = true
			out.Outputs = append(out.Outputs, c)
		}
	}
	if out.MaxOutputBytes <= 0 {
		out.MaxOutputBytes = DefaultMaxOutputBytes
	}
	return out, nil
}

// cleanOutputPath validates an output path relative to /work and returns
// its cleaned form.
func cleanOutputPath(o string) (string, error) {
	if o == "" || strings.HasPrefix(o, "/") || strings.ContainsRune(o, 0) || strings.ContainsRune(o, '\\') {
		return "", fmt.Errorf("%w: invalid output path %q", ErrInvalidPipeline, o)
	}
	for _, part := range strings.Split(o, "/") {
		if part == ".." {
			return "", fmt.Errorf("%w: output path %q contains \"..\"", ErrInvalidPipeline, o)
		}
	}
	c := path.Clean(o)
	if c == "." {
		return "", fmt.Errorf("%w: output path %q designates /work itself", ErrInvalidPipeline, o)
	}
	return c, nil
}

// sanitizeName converts s to a DNS-1123 label of at most maxLen characters.
func sanitizeName(s string, maxLen int) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		switch {
		case ok:
			b.WriteRune(r)
			dash = false
		case !dash && b.Len() > 0:
			b.WriteByte('-')
			dash = true
		}
	}
	out := b.String()
	if len(out) > maxLen {
		out = out[:maxLen]
	}
	out = strings.Trim(out, "-")
	if out == "" {
		out = "pipeline"
	}
	return out
}

// randSuffix returns n random hex characters.
func randSuffix(n int) string {
	b := make([]byte, (n+1)/2)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

func networkLabel(network bool) string {
	if network {
		return "egress"
	}
	return "none"
}

// sortedEnv returns the env map as sorted KEY=VALUE pairs with HOME=/tmp
// unless overridden.
func sortedEnv(env map[string]string) []string {
	keys := sortedKeys(env)
	out := make([]string, 0, len(keys)+1)
	if _, ok := env["HOME"]; !ok {
		out = append(out, "HOME=/tmp")
	}
	for _, k := range keys {
		out = append(out, k+"="+env[k])
	}
	return out
}

func sortedKeys(env map[string]string) []string {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// logBuffer keeps the first limit bytes written and the last tail bytes.
type logBuffer struct {
	limit int
	head  bytes.Buffer
	tail  []byte
}

func newLogBuffer(limit int) *logBuffer { return &logBuffer{limit: limit} }

func (l *logBuffer) Write(p []byte) (int, error) {
	if room := l.limit - l.head.Len(); room > 0 {
		if room > len(p) {
			room = len(p)
		}
		l.head.Write(p[:room])
	}
	l.tail = append(l.tail, p...)
	if len(l.tail) > stderrTailBytes {
		l.tail = append(l.tail[:0], l.tail[len(l.tail)-stderrTailBytes:]...)
	}
	return len(p), nil
}

// Bytes returns the (possibly truncated) head of the stream.
func (l *logBuffer) Bytes() []byte { return bytes.Clone(l.head.Bytes()) }

// Tail returns the last 2 KiB of the stream.
func (l *logBuffer) Tail() string { return string(l.tail) }

// timeoutError builds the error returned when a step exceeds its timeout.
func timeoutError(step string, d time.Duration) error {
	return fmt.Errorf("runner: step %q timed out after %s: %w", step, d, context.DeadlineExceeded)
}

// cleanupContext returns a fresh context used to release resources even when
// the run context is cancelled.
func cleanupContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), cleanupTimeout)
}

// collector accumulates output files while enforcing a total size budget.
type collector struct {
	files map[string][]byte
	total int64
	max   int64
}

func newCollector(max int64) *collector {
	return &collector{files: map[string][]byte{}, max: max}
}

// add records name (relative to /work) with content read from data.
func (c *collector) add(name string, size int64, read func(limit int64) ([]byte, error)) error {
	name = path.Clean(strings.TrimPrefix(name, "./"))
	if name == "." || strings.HasPrefix(name, "/") || name == ".." || strings.HasPrefix(name, "../") {
		return nil
	}
	if size < 0 || c.total+size > c.max {
		return fmt.Errorf("%w (%d bytes)", ErrOutputTooLarge, c.max)
	}
	data, err := read(c.max - c.total)
	if err != nil {
		return err
	}
	c.total += int64(len(data))
	c.files[name] = data
	return nil
}
