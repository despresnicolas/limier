package runner

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// Run with: RUNNER_DOCKER_IT=1 go test ./internal/runner/ -run Docker -v
func newITDocker(t *testing.T) *Docker {
	t.Helper()
	if os.Getenv("RUNNER_DOCKER_IT") != "1" {
		t.Skip("set RUNNER_DOCKER_IT=1 to run Docker integration tests")
	}
	d, err := NewDocker(DockerConfig{Host: os.Getenv("DOCKER_HOST")})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// assertNoLeftovers checks that no volume/container labelled with the
// pipeline id survives the run.
func assertNoLeftovers(t *testing.T, d *Docker, id string) {
	t.Helper()
	filters := `{"label":["` + LabelPipeline + `=` + sanitizeName(id, 40) + `"]}`
	var vols struct {
		Volumes []struct{ Name string }
	}
	if err := d.doJSON(context.Background(), "GET", "/volumes", url.Values{"filters": {filters}}, nil, &vols); err != nil {
		t.Fatal(err)
	}
	if len(vols.Volumes) != 0 {
		t.Errorf("leftover volumes: %+v", vols.Volumes)
	}
	var ctrs []struct{ ID string }
	if err := d.doJSON(context.Background(), "GET", "/containers/json", url.Values{"all": {"1"}, "filters": {filters}}, nil, &ctrs); err != nil {
		t.Fatal(err)
	}
	if len(ctrs) != 0 {
		t.Errorf("leftover containers: %+v", ctrs)
	}
}

func TestDockerIntegrationPipeline(t *testing.T) {
	d := newITDocker(t)
	id := "IT pipeline/" + randSuffix(4)
	p := Pipeline{
		ID: id,
		Steps: []Step{
			{
				Name:  "write",
				Image: "busybox:1.36",
				Cmd: []string{"sh", "-c", `echo hello > out.txt && mkdir -p d/sub && echo nested > d/sub/y.json &&
ln -s /etc/passwd d/link && echo "secret=$SECRET_TOKEN home=$HOME" >&2 && id -u && pwd`},
				Env: map[string]string{"SECRET_TOKEN": "s3cr3t"},
			},
			{
				Name:         "allowed-failure",
				Image:        "busybox:1.36",
				Cmd:          []string{"sh", "-c", "exit 3"},
				AllowFailure: true,
			},
			{
				Name:  "hardening",
				Image: "busybox:1.36",
				Cmd: []string{"sh", "-c", `touch /etc/x 2>/dev/null && echo rootfs=rw || echo rootfs=ro;
touch /tmp/x && echo tmp=rw; ls /sys/class/net | tr '\n' ' '`},
			},
		},
		Outputs: []string{"out.txt", "d", "missing.txt"},
	}
	res, err := d.Run(context.Background(), p)
	if err != nil {
		t.Fatalf("Run: %v (result %+v)", err, res)
	}
	if len(res.Steps) != 3 {
		t.Fatalf("steps = %d", len(res.Steps))
	}
	w := res.Steps[0]
	if got := string(w.Stdout); got != "65532\n/work\n" {
		t.Errorf("write stdout = %q", got)
	}
	if got := string(w.Stderr); got != "secret=s3cr3t home=/tmp\n" {
		t.Errorf("write stderr = %q", got)
	}
	if res.Steps[1].ExitCode != 3 {
		t.Errorf("allowed-failure exit = %d", res.Steps[1].ExitCode)
	}
	h := string(res.Steps[2].Stdout)
	if !strings.Contains(h, "rootfs=ro") || !strings.Contains(h, "tmp=rw") || strings.Contains(h, "eth0") {
		t.Errorf("hardening stdout = %q", h)
	}
	if got := string(res.Files["out.txt"]); got != "hello\n" {
		t.Errorf("out.txt = %q", got)
	}
	if got := string(res.Files["d/sub/y.json"]); got != "nested\n" {
		t.Errorf("d/sub/y.json = %q", got)
	}
	if len(res.Files) != 2 {
		t.Errorf("files = %v", keys(res.Files))
	}
	t.Logf("steps: %d, files: %v", len(res.Steps), keys(res.Files))
	assertNoLeftovers(t, d, id)
}

func TestDockerIntegrationStepError(t *testing.T) {
	d := newITDocker(t)
	id := "it-fail-" + randSuffix(4)
	res, err := d.Run(context.Background(), Pipeline{
		ID: id,
		Steps: []Step{
			{Name: "boom", Image: "busybox:1.36", Cmd: []string{"sh", "-c", "echo bad >&2; exit 7"}},
			{Name: "never", Image: "busybox:1.36", Cmd: []string{"true"}},
		},
	})
	var se *StepError
	if !errors.As(err, &se) {
		t.Fatalf("err = %v, want *StepError", err)
	}
	if se.Step != "boom" || se.ExitCode != 7 || se.Stderr != "bad\n" {
		t.Errorf("StepError = %+v", se)
	}
	if res == nil || len(res.Steps) != 1 {
		t.Errorf("partial result = %+v", res)
	}
	assertNoLeftovers(t, d, id)
}

func TestDockerIntegrationTimeout(t *testing.T) {
	d := newITDocker(t)
	id := "it-timeout-" + randSuffix(4)
	start := time.Now()
	_, err := d.Run(context.Background(), Pipeline{
		ID: id,
		Steps: []Step{
			{Name: "slow", Image: "busybox:1.36", Cmd: []string{"sleep", "60"}, Timeout: 2 * time.Second},
		},
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
	if time.Since(start) > 30*time.Second {
		t.Errorf("timeout not honored: %s", time.Since(start))
	}
	assertNoLeftovers(t, d, id)

	// Pipeline-level cancellation.
	id = "it-cancel-" + randSuffix(4)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = d.Run(ctx, Pipeline{
		ID:    id,
		Steps: []Step{{Name: "slow", Image: "busybox:1.36", Cmd: []string{"sleep", "60"}}},
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
	assertNoLeftovers(t, d, id)
}

func TestDockerIntegrationMaxOutput(t *testing.T) {
	d := newITDocker(t)
	_, err := d.Run(context.Background(), Pipeline{
		ID:             "it-max-" + randSuffix(4),
		Steps:          []Step{{Name: "big", Image: "busybox:1.36", Cmd: []string{"sh", "-c", "head -c 4096 /dev/zero > big"}}},
		Outputs:        []string{"big"},
		MaxOutputBytes: 1024,
	})
	if !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("err = %v, want ErrOutputTooLarge", err)
	}
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
