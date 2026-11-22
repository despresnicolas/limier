package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

// DockerConfig configures the Docker runner.
type DockerConfig struct {
	// Host is the Docker Engine endpoint: "unix:///var/run/docker.sock"
	// (default), "tcp://host:port" (plain HTTP), "http://..." or "https://...".
	Host string
	// APIVersion is the Engine API version path prefix (default "v1.43").
	APIVersion string
	// Network is the docker network used when Step.Network is true (default
	// "bridge").
	Network string
	// HelperImage is a small image used for volume initialisation and output
	// collection. It must provide a chown binary (default "busybox:1.36").
	HelperImage string
	// MemoryBytes is the per-container memory limit (default 4 GiB). Swap is
	// disabled.
	MemoryBytes int64
	// NanoCPUs is the per-container CPU limit (default 2 CPUs).
	NanoCPUs int64
	// PullPolicy is "missing" (default), "always" or "never".
	PullPolicy string
	// RegistryAuth is an optional base64url-encoded JSON auth config sent as
	// X-Registry-Auth when pulling images.
	RegistryAuth string
	// HTTPClient overrides the HTTP client (mainly for tests). When set, Host
	// is only used to build request URLs.
	HTTPClient *http.Client
}

// Pull policies.
const (
	PullMissing = "missing"
	PullAlways  = "always"
	PullNever   = "never"
)

// Docker runs pipelines with the Docker Engine API. It implements Runner.
//
// Each pipeline gets a dedicated named volume mounted at /work, initialised
// by a root helper container that only holds CAP_CHOWN. Steps then run
// sequentially in hardened containers (read-only rootfs, tmpfs /tmp, all
// capabilities dropped, no-new-privileges, pids/memory/cpu limits, no network
// unless requested). Outputs are fetched through the container archive
// endpoint (GET /containers/{id}/archive) of a never-started helper container
// mounting the volume read-only: unlike container logs this is binary safe
// and not subject to log driver rotation or size limits.
type Docker struct {
	cfg     DockerConfig
	client  *http.Client
	baseURL string
}

var _ Runner = (*Docker)(nil)

// NewDocker builds a Docker runner from cfg, applying defaults.
func NewDocker(cfg DockerConfig) (*Docker, error) {
	if cfg.Host == "" {
		cfg.Host = "unix:///var/run/docker.sock"
	}
	if cfg.APIVersion == "" {
		cfg.APIVersion = "v1.43"
	}
	if !strings.HasPrefix(cfg.APIVersion, "v") {
		cfg.APIVersion = "v" + cfg.APIVersion
	}
	if cfg.Network == "" {
		cfg.Network = "bridge"
	}
	if cfg.HelperImage == "" {
		cfg.HelperImage = "busybox:1.36"
	}
	if cfg.MemoryBytes <= 0 {
		cfg.MemoryBytes = 4 << 30
	}
	if cfg.NanoCPUs <= 0 {
		cfg.NanoCPUs = 2e9
	}
	switch cfg.PullPolicy {
	case "":
		cfg.PullPolicy = PullMissing
	case PullMissing, PullAlways, PullNever:
	default:
		return nil, fmt.Errorf("runner: unknown docker pull policy %q", cfg.PullPolicy)
	}

	u, err := url.Parse(cfg.Host)
	if err != nil {
		return nil, fmt.Errorf("runner: invalid docker host %q: %w", cfg.Host, err)
	}
	var base string
	transport := http.DefaultTransport.(*http.Transport).Clone()
	switch u.Scheme {
	case "unix":
		sock := u.Path
		if sock == "" {
			return nil, fmt.Errorf("runner: invalid docker host %q: empty socket path", cfg.Host)
		}
		transport.Proxy = nil
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		}
		base = "http://docker"
	case "tcp", "http":
		base = "http://" + u.Host
	case "https":
		base = "https://" + u.Host
	default:
		return nil, fmt.Errorf("runner: unsupported docker host scheme %q", u.Scheme)
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Transport: transport}
	}
	return &Docker{cfg: cfg, client: client, baseURL: base + "/" + cfg.APIVersion}, nil
}

// Run implements Runner.
func (d *Docker) Run(ctx context.Context, p Pipeline) (*Result, error) {
	p, err := normalize(p)
	if err != nil {
		return nil, err
	}
	res := &Result{Files: map[string][]byte{}}
	id := sanitizeName(p.ID, 40)
	prefix := "limier-" + id + "-" + randSuffix(6)
	volume := prefix + "-work"
	labels := map[string]string{LabelPipeline: id}

	pulled := map[string]bool{}
	ensure := func(image string) error {
		if pulled[image] {
			return nil
		}
		if err := d.ensureImage(ctx, image); err != nil {
			return err
		}
		pulled[image] = true
		return nil
	}

	if err := d.createVolume(ctx, volume, labels); err != nil {
		return res, err
	}
	defer func() {
		cctx, cancel := cleanupContext()
		defer cancel()
		_ = d.removeVolume(cctx, volume)
	}()

	// Volume initialisation: make /work writable by the unprivileged user.
	// Every bind uses "nocopy": otherwise Docker copies the (root-owned)
	// image directory over the still-empty volume on each mount, resetting
	// the ownership set here.
	if err := ensure(d.cfg.HelperImage); err != nil {
		return res, err
	}
	initSpec := containerSpec{
		name:     prefix + "-init",
		image:    d.cfg.HelperImage,
		cmd:      []string{"chown", DefaultUser, WorkDir},
		user:     "0:0",
		workDir:  "/",
		labels:   labels,
		capAdd:   []string{"CHOWN"},
		binds:    []string{volume + ":" + WorkDir + ":nocopy"},
		network:  "none",
		readOnly: true,
	}
	code, _, err := d.runContainer(ctx, initSpec, io.Discard, io.Discard)
	if err != nil {
		return res, fmt.Errorf("runner: initialising work volume: %w", err)
	}
	if code != 0 {
		return res, fmt.Errorf("runner: initialising work volume: chown exited with code %d", code)
	}

	for i, s := range p.Steps {
		if err := ctx.Err(); err != nil {
			return res, fmt.Errorf("runner: pipeline aborted before step %q: %w", s.Name, err)
		}
		if err := ensure(s.Image); err != nil {
			return res, err
		}
		stepCtx, cancel := ctx, context.CancelFunc(func() {})
		if s.Timeout > 0 {
			stepCtx, cancel = context.WithTimeout(ctx, s.Timeout)
		}
		network := "none"
		if s.Network {
			network = d.cfg.Network
		}
		stepLabels := map[string]string{LabelPipeline: id, LabelStep: fmt.Sprint(i), LabelNetwork: networkLabel(s.Network)}
		binds := []string{volume + ":" + WorkDir + ":nocopy"}
		for _, m := range s.Mounts {
			mode := ":ro"
			if m.Writable {
				mode = ":rw"
			}
			binds = append(binds, m.Source+":"+m.Target+mode)
		}
		spec := containerSpec{
			name:     fmt.Sprintf("%s-%d-%s", prefix, i, sanitizeName(s.Name, 20)),
			image:    s.Image,
			cmd:      s.Cmd,
			env:      sortedEnv(s.Env),
			user:     s.User,
			workDir:  s.WorkingDir,
			labels:   stepLabels,
			binds:    binds,
			network:  network,
			readOnly: true,
		}
		stdout, stderr := newLogBuffer(MaxLogBytes), newLogBuffer(MaxLogBytes)
		code, dur, err := d.runContainer(stepCtx, spec, stdout, stderr)
		cancel()
		res.Steps = append(res.Steps, StepResult{
			Name: s.Name, ExitCode: code, Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), Duration: dur,
		})
		if err != nil {
			if ctx.Err() == nil && stepCtx.Err() != nil {
				return res, timeoutError(s.Name, s.Timeout)
			}
			return res, fmt.Errorf("runner: step %q: %w", s.Name, err)
		}
		if code != 0 && !s.AllowFailure {
			return res, &StepError{Step: s.Name, ExitCode: code, Stderr: stderr.Tail()}
		}
	}

	if len(p.Outputs) > 0 {
		if err := d.collect(ctx, prefix, volume, labels, p, res); err != nil {
			return res, err
		}
	}
	return res, nil
}

// collect copies the pipeline outputs out of the work volume.
func (d *Docker) collect(ctx context.Context, prefix, volume string, labels map[string]string, p Pipeline, res *Result) error {
	spec := containerSpec{
		name:     prefix + "-collect",
		image:    d.cfg.HelperImage,
		cmd:      []string{"true"},
		user:     DefaultUser,
		workDir:  WorkDir,
		labels:   labels,
		binds:    []string{volume + ":" + WorkDir + ":ro,nocopy"},
		network:  "none",
		readOnly: true,
	}
	cid, err := d.createContainer(ctx, spec)
	if err != nil {
		return fmt.Errorf("runner: collecting outputs: %w", err)
	}
	defer d.removeContainer(cid)

	c := newCollector(p.MaxOutputBytes)
	for _, o := range p.Outputs {
		q := url.Values{"path": {path.Join(WorkDir, o)}}
		resp, err := d.do(ctx, http.MethodGet, "/containers/"+cid+"/archive", q, nil)
		if isNotFound(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("runner: collecting output %q: %w", o, err)
		}
		err = extractTar(resp.Body, path.Dir(o), c)
		resp.Body.Close()
		if err != nil {
			res.Files = c.files
			return err
		}
	}
	res.Files = c.files
	return nil
}

// containerSpec is the runner-level description of a container.
type containerSpec struct {
	name     string
	image    string
	cmd      []string
	env      []string
	user     string
	workDir  string
	labels   map[string]string
	capAdd   []string
	binds    []string
	network  string
	readOnly bool
}

type dockerHostConfig struct {
	Binds          []string          `json:"Binds,omitempty"`
	ReadonlyRootfs bool              `json:"ReadonlyRootfs"`
	Tmpfs          map[string]string `json:"Tmpfs,omitempty"`
	CapDrop        []string          `json:"CapDrop"`
	CapAdd         []string          `json:"CapAdd,omitempty"`
	SecurityOpt    []string          `json:"SecurityOpt"`
	NetworkMode    string            `json:"NetworkMode"`
	Memory         int64             `json:"Memory"`
	MemorySwap     int64             `json:"MemorySwap"`
	NanoCPUs       int64             `json:"NanoCpus"`
	PidsLimit      int64             `json:"PidsLimit"`
	AutoRemove     bool              `json:"AutoRemove"`
}

type dockerCreateRequest struct {
	Image      string            `json:"Image"`
	Entrypoint []string          `json:"Entrypoint,omitempty"`
	Cmd        []string          `json:"Cmd,omitempty"`
	Env        []string          `json:"Env,omitempty"`
	User       string            `json:"User"`
	WorkingDir string            `json:"WorkingDir"`
	Labels     map[string]string `json:"Labels"`
	HostConfig dockerHostConfig  `json:"HostConfig"`
}

// createRequest builds the container creation payload for spec.
func (d *Docker) createRequest(spec containerSpec) dockerCreateRequest {
	req := dockerCreateRequest{
		Image:      spec.image,
		Env:        spec.env,
		User:       spec.user,
		WorkingDir: spec.workDir,
		Labels:     spec.labels,
		HostConfig: dockerHostConfig{
			Binds:          spec.binds,
			ReadonlyRootfs: spec.readOnly,
			Tmpfs:          map[string]string{"/tmp": "rw,size=1g,mode=1777"},
			CapDrop:        []string{"ALL"},
			CapAdd:         spec.capAdd,
			SecurityOpt:    []string{"no-new-privileges"},
			NetworkMode:    spec.network,
			Memory:         d.cfg.MemoryBytes,
			MemorySwap:     d.cfg.MemoryBytes,
			NanoCPUs:       d.cfg.NanoCPUs,
			PidsLimit:      1024,
			AutoRemove:     false,
		},
	}
	if len(spec.cmd) > 0 {
		// Exec form: the full argv replaces the image ENTRYPOINT and CMD.
		req.Entrypoint = spec.cmd
	}
	return req
}

func (d *Docker) createContainer(ctx context.Context, spec containerSpec) (string, error) {
	var out struct {
		ID string `json:"Id"`
	}
	q := url.Values{"name": {spec.name}}
	if err := d.doJSON(ctx, http.MethodPost, "/containers/create", q, d.createRequest(spec), &out); err != nil {
		return "", fmt.Errorf("creating container: %w", err)
	}
	return out.ID, nil
}

// removeContainer force-removes a container using a fresh context.
func (d *Docker) removeContainer(id string) {
	ctx, cancel := cleanupContext()
	defer cancel()
	resp, err := d.do(ctx, http.MethodDelete, "/containers/"+id, url.Values{"force": {"1"}, "v": {"1"}}, nil)
	if err == nil {
		resp.Body.Close()
	}
}

// runContainer creates, starts and waits for a container, copies its logs to
// stdout/stderr and removes it. When ctx ends first the container is killed
// and ctx's error is returned.
func (d *Docker) runContainer(ctx context.Context, spec containerSpec, stdout, stderr io.Writer) (int, time.Duration, error) {
	id, err := d.createContainer(ctx, spec)
	if err != nil {
		return -1, 0, err
	}
	defer d.removeContainer(id)

	start := time.Now()
	resp, err := d.do(ctx, http.MethodPost, "/containers/"+id+"/start", nil, nil)
	if err != nil {
		return -1, 0, fmt.Errorf("starting container: %w", err)
	}
	resp.Body.Close()

	var wait struct {
		StatusCode int `json:"StatusCode"`
		Error      *struct {
			Message string `json:"Message"`
		} `json:"Error"`
	}
	werr := d.doJSON(ctx, http.MethodPost, "/containers/"+id+"/wait", url.Values{"condition": {"not-running"}}, nil, &wait)
	dur := time.Since(start)

	cctx, cancel := cleanupContext()
	defer cancel()
	if werr != nil {
		// Timeout, cancellation or daemon failure: stop the container, keep
		// whatever it logged.
		if r, err := d.do(cctx, http.MethodPost, "/containers/"+id+"/kill", nil, nil); err == nil {
			r.Body.Close()
		}
		_ = d.logs(cctx, id, stdout, stderr)
		if ctx.Err() != nil {
			return -1, dur, ctx.Err()
		}
		return -1, dur, fmt.Errorf("waiting for container: %w", werr)
	}
	if err := d.logs(cctx, id, stdout, stderr); err != nil {
		return wait.StatusCode, dur, fmt.Errorf("reading container logs: %w", err)
	}
	if wait.Error != nil && wait.Error.Message != "" {
		return wait.StatusCode, dur, fmt.Errorf("waiting for container: %s", wait.Error.Message)
	}
	return wait.StatusCode, dur, nil
}

// logs copies the demultiplexed container logs to stdout and stderr.
func (d *Docker) logs(ctx context.Context, id string, stdout, stderr io.Writer) error {
	resp, err := d.do(ctx, http.MethodGet, "/containers/"+id+"/logs", url.Values{"stdout": {"1"}, "stderr": {"1"}}, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return demux(resp.Body, stdout, stderr)
}

func (d *Docker) createVolume(ctx context.Context, name string, labels map[string]string) error {
	body := map[string]any{"Name": name, "Labels": labels}
	if err := d.doJSON(ctx, http.MethodPost, "/volumes/create", nil, body, nil); err != nil {
		return fmt.Errorf("runner: creating volume: %w", err)
	}
	return nil
}

func (d *Docker) removeVolume(ctx context.Context, name string) error {
	resp, err := d.do(ctx, http.MethodDelete, "/volumes/"+name, url.Values{"force": {"1"}}, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// ensureImage makes image available locally according to the pull policy.
func (d *Docker) ensureImage(ctx context.Context, image string) error {
	switch d.cfg.PullPolicy {
	case PullNever:
		return nil
	case PullMissing:
		resp, err := d.do(ctx, http.MethodGet, "/images/"+image+"/json", nil, nil)
		if err == nil {
			resp.Body.Close()
			return nil
		}
		if !isNotFound(err) {
			return fmt.Errorf("runner: inspecting image %q: %w", image, err)
		}
	}
	return d.pullImage(ctx, image)
}

// pullImage pulls image and consumes the progress stream fully.
func (d *Docker) pullImage(ctx context.Context, image string) error {
	q := url.Values{"fromImage": {image}}
	if !hasTagOrDigest(image) {
		q.Set("tag", "latest") // an empty tag would pull every tag
	}
	resp, err := d.do(ctx, http.MethodPost, "/images/create", q, nil)
	if err != nil {
		return fmt.Errorf("runner: pulling image %q: %w", image, err)
	}
	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	for {
		var msg struct {
			Error       string `json:"error"`
			ErrorDetail struct {
				Message string `json:"message"`
			} `json:"errorDetail"`
		}
		if err := dec.Decode(&msg); errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return fmt.Errorf("runner: pulling image %q: %w", image, err)
		}
		if msg.Error != "" {
			return fmt.Errorf("runner: pulling image %q: %s", image, msg.Error)
		}
	}
}

// hasTagOrDigest reports whether an image reference carries a tag or digest.
func hasTagOrDigest(ref string) bool {
	if strings.Contains(ref, "@") {
		return true
	}
	return strings.Contains(ref[strings.LastIndex(ref, "/")+1:], ":")
}

// apiError is a non-2xx response from the Docker Engine.
type apiError struct {
	Status  int
	Message string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("docker API: %d: %s", e.Status, e.Message)
}

func isNotFound(err error) bool {
	var ae *apiError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

// do performs a request and returns the response when the status is 2xx.
// The caller must close the body.
func (d *Docker) do(ctx context.Context, method, p string, q url.Values, body any) (*http.Response, error) {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		r = strings.NewReader(string(b))
	}
	u := d.baseURL + p
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, r)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if d.cfg.RegistryAuth != "" && p == "/images/create" {
		req.Header.Set("X-Registry-Auth", d.cfg.RegistryAuth)
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		var m struct {
			Message string `json:"message"`
		}
		msg := strings.TrimSpace(string(b))
		if json.Unmarshal(b, &m) == nil && m.Message != "" {
			msg = m.Message
		}
		return nil, &apiError{Status: resp.StatusCode, Message: msg}
	}
	return resp, nil
}

// doJSON performs a request and decodes the JSON response into out (if not
// nil).
func (d *Docker) doJSON(ctx context.Context, method, p string, q url.Values, body, out any) error {
	resp, err := d.do(ctx, method, p, q, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
