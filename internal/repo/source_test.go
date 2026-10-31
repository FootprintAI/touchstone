package repo

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func makeTarball(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestLatestSemverTag(t *testing.T) {
	got, ok := LatestSemverTag([]string{"v1.2.0", "v1.10.0", "v2.0.0-rc.1", "nightly", "v1.9.9", "1.3"})
	if !ok || got != "v1.10.0" {
		t.Fatalf("got %q, %v; want v1.10.0", got, ok)
	}
	if got, ok := LatestSemverTag([]string{"v2.0.0-beta", "latest"}); ok {
		t.Fatalf("got %q; want no release", got)
	}
}

func TestExtractLockfiles(t *testing.T) {
	tb := makeTarball(t, map[string]string{
		"r-v1/package-lock.json": `{"lockfileVersion":3,"packages":{"":{"version":"1.0.0"},"node_modules/left-pad":{"version":"1.3.0"},"node_modules/@a/b":{"version":"2.0.0"}}}`,
		"r-v1/requirements.txt":  "# c\nrequests==2.31.0\nflask>=2.0\nPyYAML[x]==6.0 ; python_version>'3'\n-r other.txt\n",
		"r-v1/go.mod":            "module x\n\nrequire (\n\tgolang.org/x/net v0.1.0 // indirect\n)\nrequire github.com/a/b v1.0.0\n",
		"r-v1/pom.xml":           `<project><properties><j.v>2.9.0</j.v></properties><dependencies><dependency><groupId>com.x</groupId><artifactId>j</artifactId><version>${j.v}</version></dependency><dependency><groupId>com.x</groupId><artifactId>r</artifactId><version>[1,2)</version></dependency></dependencies></project>`,
		"r-v1/node_modules/z/package-lock.json": `{"packages":{"node_modules/skip":{"version":"1.0.0"}}}`,
	})
	deps, err := ExtractLockfiles(tb)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, d := range deps {
		got[d.Path+"|"+d.Purl] = true
	}
	for _, want := range []string{
		"package-lock.json|pkg:npm/left-pad@1.3.0",
		"package-lock.json|pkg:npm/%40a/b@2.0.0",
		"requirements.txt|pkg:pypi/requests@2.31.0",
		"requirements.txt|pkg:pypi/pyyaml@6.0",
		"go.mod|pkg:golang/golang.org/x/net@v0.1.0",
		"go.mod|pkg:golang/github.com/a/b@v1.0.0",
		"pom.xml|pkg:maven/com.x/j@2.9.0",
	} {
		if !got[want] {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	if len(deps) != 7 {
		t.Errorf("got %d deps, want 7: %+v", len(deps), deps)
	}
}

func TestExtractNoLockfile(t *testing.T) {
	tb := makeTarball(t, map[string]string{"r/package.json": `{"dependencies":{"a":"^1.0.0"}}`})
	if _, err := ExtractLockfiles(tb); !errors.Is(err, ErrNoLockfile) {
		t.Fatalf("got %v, want ErrNoLockfile", err)
	}
}

func TestSourceReleaseEvidence(t *testing.T) {
	f := NewFake("github")
	f.Releases["https://github.com/o/r"] = &Release{Tag: "v1.2.0", TarballURL: "t"}
	f.Tarballs["t"] = makeTarball(t, map[string]string{"o-r-abc/package-lock.json": `{"packages":{"node_modules/a":{"version":"1.0.0"}}}`})
	comps, err := (&Source{RepoURL: "https://github.com/o/r", Forges: []Forge{f}}).Collect(context.Background(), "")
	if err != nil || len(comps) != 1 {
		t.Fatalf("got %v, %v", comps, err)
	}
	c := comps[0]
	if c.Confidence != "MEDIUM" || c.Evidence[0].Location != "o/r@v1.2.0:package-lock.json" || len(c.Caveats) != 0 {
		t.Fatalf("unexpected component %+v", c)
	}
}

func TestSourceDefaultBranchCaveat(t *testing.T) {
	f := NewFake("github")
	f.Releases["https://github.com/o/r"] = &Release{Tag: "main", TarballURL: "t", DefaultBranch: true}
	f.Tarballs["t"] = makeTarball(t, map[string]string{"x/go.mod": "module m\nrequire a.b/c v1.0.0\n"})
	comps, err := (&Source{RepoURL: "https://github.com/o/r", Forges: []Forge{f}}).Collect(context.Background(), "")
	if err != nil || len(comps) != 1 || comps[0].Caveats[0] != CaveatDefaultBranch {
		t.Fatalf("got %+v, %v", comps, err)
	}
}

func TestSourceNoLockfileStatus(t *testing.T) {
	f := NewFake("github")
	f.Releases["https://github.com/o/r"] = &Release{Tag: "v1.0.0", TarballURL: "t"}
	f.Tarballs["t"] = makeTarball(t, map[string]string{"x/README.md": "hi"})
	_, err := (&Source{RepoURL: "https://github.com/o/r", Forges: []Forge{f}}).Collect(context.Background(), "")
	if !errors.Is(err, ErrNoLockfile) {
		t.Fatalf("got %v, want ErrNoLockfile", err)
	}
}

func TestGitHubLatestReleaseAndFallback(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/o/tagged/tags", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`[{"name":"v1.0.0"},{"name":"v1.1.0"},{"name":"v2.0.0-rc1"}]`))
	})
	mux.HandleFunc("/repos/o/bare/tags", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`[]`)) })
	mux.HandleFunc("/repos/o/bare", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"default_branch":"trunk"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	g := NewGitHub(srv.URL, "tok", srv.Client())

	rel, err := g.LatestRelease(context.Background(), "https://github.com/o/tagged")
	if err != nil || rel.Tag != "v1.1.0" || rel.DefaultBranch {
		t.Fatalf("got %+v, %v", rel, err)
	}
	rel, err = g.LatestRelease(context.Background(), "https://github.com/o/bare")
	if err != nil || rel.Tag != "trunk" || !rel.DefaultBranch {
		t.Fatalf("got %+v, %v", rel, err)
	}
	if _, err := g.FetchTarball(context.Background(), "https://evil.example/x"); err == nil {
		t.Fatal("want refusal for foreign tarball URL")
	}
}
