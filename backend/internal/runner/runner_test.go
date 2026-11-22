package runner

import (
	"archive/tar"
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func TestSanitizeName(t *testing.T) {
	cases := map[string]string{
		"Scan/Project_42:abc":   "scan-project-42-abc",
		"--x--":                 "x",
		"":                      "pipeline",
		"ÉtÉ":                   "t",
		strings.Repeat("a", 80): strings.Repeat("a", 40),
	}
	for in, want := range cases {
		if got := sanitizeName(in, 40); got != want {
			t.Errorf("sanitizeName(%q) = %q, want %q", in, got, want)
		}
	}
	if got := sanitizeName("abc-"+strings.Repeat("-", 50), 5); got != "abc" {
		t.Errorf("trailing dash not trimmed: %q", got)
	}
}

func TestNormalize(t *testing.T) {
	_, err := normalize(Pipeline{})
	if !errors.Is(err, ErrInvalidPipeline) {
		t.Fatalf("empty pipeline: %v", err)
	}
	for _, bad := range []string{"/etc/passwd", "../x", "a/../../b", "a/..", "", ".", "a\\b"} {
		_, err := normalize(Pipeline{Steps: []Step{{Image: "x"}}, Outputs: []string{bad}})
		if !errors.Is(err, ErrInvalidPipeline) {
			t.Errorf("output %q accepted", bad)
		}
	}
	_, err = normalize(Pipeline{Steps: []Step{{Image: "x", Env: map[string]string{"A=B": "c"}}}})
	if !errors.Is(err, ErrInvalidPipeline) {
		t.Errorf("invalid env name accepted")
	}
	p, err := normalize(Pipeline{Steps: []Step{{Image: "x"}}, Outputs: []string{"./a//b.json", "a/b.json"}})
	if err != nil {
		t.Fatal(err)
	}
	s := p.Steps[0]
	if s.User != DefaultUser || s.WorkingDir != "/work" || s.Name != "step-0" || p.MaxOutputBytes != DefaultMaxOutputBytes {
		t.Errorf("defaults not applied: %+v %d", s, p.MaxOutputBytes)
	}
	if len(p.Outputs) != 1 || p.Outputs[0] != "a/b.json" {
		t.Errorf("outputs = %v", p.Outputs)
	}
}

func TestSortedEnv(t *testing.T) {
	got := sortedEnv(map[string]string{"B": "2", "A": "1"})
	want := []string{"HOME=/tmp", "A=1", "B=2"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("sortedEnv = %v", got)
	}
	if got := sortedEnv(map[string]string{"HOME": "/h"}); len(got) != 1 || got[0] != "HOME=/h" {
		t.Errorf("HOME override = %v", got)
	}
}

func frame(stream byte, payload string) []byte {
	h := make([]byte, 8)
	h[0] = stream
	binary.BigEndian.PutUint32(h[4:], uint32(len(payload)))
	return append(h, payload...)
}

func TestDemux(t *testing.T) {
	var in bytes.Buffer
	in.Write(frame(1, "out1 "))
	in.Write(frame(2, "err1"))
	in.Write(frame(1, "out2"))
	in.Write(frame(1, ""))
	var out, errb bytes.Buffer
	if err := demux(&in, &out, &errb); err != nil {
		t.Fatal(err)
	}
	if out.String() != "out1 out2" || errb.String() != "err1" {
		t.Errorf("stdout=%q stderr=%q", out.String(), errb.String())
	}
	truncated := frame(1, "abcdef")[:10]
	if err := demux(bytes.NewReader(truncated), &out, &errb); err == nil {
		t.Error("truncated frame accepted")
	}
	if err := demux(bytes.NewReader(frame(3, "boom")), &out, &errb); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("system error frame: %v", err)
	}
}

func TestLogBuffer(t *testing.T) {
	l := newLogBuffer(4)
	l.Write([]byte("abc"))
	l.Write([]byte("defgh"))
	if string(l.Bytes()) != "abcd" {
		t.Errorf("head = %q", l.Bytes())
	}
	if l.Tail() != "abcdefgh" {
		t.Errorf("tail = %q", l.Tail())
	}
	big := newLogBuffer(MaxLogBytes)
	big.Write(bytes.Repeat([]byte("x"), 3000))
	big.Write([]byte("END"))
	if tail := big.Tail(); len(tail) != stderrTailBytes || !strings.HasSuffix(tail, "END") {
		t.Errorf("tail len=%d", len(tail))
	}
}

func makeTar(t *testing.T, files map[string]string, symlink string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(content))
	}
	if symlink != "" {
		tw.WriteHeader(&tar.Header{Name: symlink, Linkname: "/etc/passwd", Typeflag: tar.TypeSymlink})
	}
	tw.Close()
	return buf.Bytes()
}

func TestExtractTar(t *testing.T) {
	data := makeTar(t, map[string]string{"report.json": "{}", "../escape": "x", "./sub/a": "a"}, "link")
	c := newCollector(1 << 20)
	if err := extractTar(bytes.NewReader(data), "out", c); err != nil {
		t.Fatal(err)
	}
	if string(c.files["out/report.json"]) != "{}" || string(c.files["out/sub/a"]) != "a" {
		t.Errorf("files = %v", c.files)
	}
	if _, ok := c.files["escape"]; ok {
		t.Error("tar entry escaped the prefix")
	}
	if _, ok := c.files["out/link"]; ok {
		t.Error("symlink collected")
	}

	c = newCollector(1 << 20)
	extractTar(bytes.NewReader(makeTar(t, map[string]string{"../../x": "x"}, "")), "", c)
	if len(c.files) != 0 {
		t.Errorf("escaping entry collected: %v", c.files)
	}

	c = newCollector(3)
	err := extractTar(bytes.NewReader(makeTar(t, map[string]string{"a": "12", "b": "34"}, "")), "", c)
	if !errors.Is(err, ErrOutputTooLarge) {
		t.Errorf("err = %v, want ErrOutputTooLarge", err)
	}
}

func TestHasTagOrDigest(t *testing.T) {
	cases := map[string]bool{
		"busybox":                  false,
		"busybox:1.36":             true,
		"localhost:5000/img":       false,
		"localhost:5000/img:v1":    true,
		"ghcr.io/a/b@sha256:abcd":  true,
		"registry.example.com/a/b": false,
	}
	for in, want := range cases {
		if got := hasTagOrDigest(in); got != want {
			t.Errorf("hasTagOrDigest(%q) = %v", in, got)
		}
	}
}

func TestNormalizeMounts(t *testing.T) {
	base := Pipeline{ID: "x", Steps: []Step{{Image: "busybox"}}}
	for _, m := range []Mount{
		{Source: "relative", Target: "/source"},
		{Source: "/src", Target: "/work/src"},
		{Source: "/src", Target: "/work"},
		{Source: "/src", Target: "/"},
		{Source: "/src:rw", Target: "/source"},
	} {
		p := base
		p.Steps = []Step{{Image: "busybox", Mounts: []Mount{m}}}
		if _, err := normalize(p); !errors.Is(err, ErrInvalidPipeline) {
			t.Errorf("mount %+v should be rejected, got %v", m, err)
		}
	}
	p := base
	p.Steps = []Step{{Image: "busybox", Mounts: []Mount{{Source: "/repos/app", Target: "/source"}}}}
	if _, err := normalize(p); err != nil {
		t.Fatal(err)
	}
}
