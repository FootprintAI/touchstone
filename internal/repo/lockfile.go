package repo

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"sort"
	"strings"
)

// ErrNoLockfile means the tarball holds no supported lockfile. Dependencies
// are not guessed from manifest ranges.
var ErrNoLockfile = errors.New("no lockfile, dependencies not resolvable")

const (
	maxLockfileBytes = 20 << 20
	maxTarEntries    = 200000
)

// Dependency is one pinned package read from a lockfile.
type Dependency struct {
	Name    string
	Version string
	Purl    string
	// Path is the lockfile's path inside the repo.
	Path string
}

// extractors maps a lockfile's base name to its parser.
var extractors = map[string]func([]byte) ([]Dependency, error){
	"package-lock.json": parsePackageLock,
	"requirements.txt":  parseRequirements,
	"go.mod":            parseGoMod,
	"pom.xml":           parsePOM,
}

// ExtractLockfiles reads a gzipped repo tarball and returns the pinned
// dependencies of every supported lockfile outside node_modules/vendor
// directories. The tarball's single top-level directory is stripped, so
// paths are repo-relative. It returns ErrNoLockfile when none is found.
func ExtractLockfiles(tarball []byte) ([]Dependency, error) {
	zr, err := gzip.NewReader(bytes.NewReader(tarball))
	if err != nil {
		return nil, fmt.Errorf("repo: tarball: %w", err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)

	var deps []Dependency
	found := false
	for n := 0; ; n++ {
		if n > maxTarEntries {
			return nil, errors.New("repo: tarball has too many entries")
		}
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("repo: tarball: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		rel := stripTop(h.Name)
		parse, ok := extractors[path.Base(rel)]
		if !ok || rel == "" || skipDir(rel) {
			continue
		}
		if h.Size > maxLockfileBytes {
			return nil, fmt.Errorf("repo: lockfile %s is larger than %d bytes", rel, maxLockfileBytes)
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxLockfileBytes))
		if err != nil {
			return nil, fmt.Errorf("repo: tarball: %w", err)
		}
		ds, err := parse(data)
		if err != nil {
			return nil, fmt.Errorf("repo: %s: %w", rel, err)
		}
		found = true
		for _, d := range ds {
			d.Path = rel
			deps = append(deps, d)
		}
	}
	if !found {
		return nil, ErrNoLockfile
	}
	sort.SliceStable(deps, func(i, j int) bool {
		if deps[i].Path != deps[j].Path {
			return deps[i].Path < deps[j].Path
		}
		if deps[i].Name != deps[j].Name {
			return deps[i].Name < deps[j].Name
		}
		return deps[i].Version < deps[j].Version
	})
	return deps, nil
}

// stripTop drops the first path element and returns "" for unsafe paths.
func stripTop(name string) string {
	name = path.Clean(strings.TrimPrefix(name, "./"))
	i := strings.IndexByte(name, '/')
	if i < 0 {
		return ""
	}
	rest := name[i+1:]
	if rest == "" || strings.HasPrefix(rest, "../") || rest == ".." || strings.HasPrefix(rest, "/") {
		return ""
	}
	return rest
}

func skipDir(rel string) bool {
	for _, seg := range strings.Split(path.Dir(rel), "/") {
		if seg == "node_modules" || seg == "vendor" {
			return true
		}
	}
	return false
}

func npmPurl(name, version string) string {
	if strings.HasPrefix(name, "@") {
		name = "%40" + name[1:]
	}
	return "pkg:npm/" + name + "@" + version
}

type npmLock struct {
	Packages     map[string]npmPkg `json:"packages"`
	Dependencies map[string]npmPkg `json:"dependencies"`
}

type npmPkg struct {
	Version      string            `json:"version"`
	Link         bool              `json:"link"`
	Dependencies map[string]npmPkg `json:"dependencies"`
}

func parsePackageLock(data []byte) ([]Dependency, error) {
	var l npmLock
	if err := json.Unmarshal(data, &l); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []Dependency
	add := func(name, version string) {
		if name == "" || version == "" || seen[name+"@"+version] {
			return
		}
		seen[name+"@"+version] = true
		out = append(out, Dependency{Name: name, Version: version, Purl: npmPurl(name, version)})
	}
	if len(l.Packages) > 0 { // lockfileVersion 2 and 3
		for key, p := range l.Packages {
			i := strings.LastIndex(key, "node_modules/")
			if key == "" || i < 0 || p.Link {
				continue
			}
			add(key[i+len("node_modules/"):], p.Version)
		}
		return out, nil
	}
	var walk func(map[string]npmPkg)
	walk = func(m map[string]npmPkg) { // lockfileVersion 1
		for name, p := range m {
			add(name, p.Version)
			walk(p.Dependencies)
		}
	}
	walk(l.Dependencies)
	return out, nil
}

// parseRequirements reads only exact pins (name==1.2.3). Ranges and
// unpinned names are skipped: a version is never guessed.
func parseRequirements(data []byte) ([]Dependency, error) {
	var out []Dependency
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.Index(line, " #"); i >= 0 {
			line = line[:i]
		}
		if i := strings.IndexByte(line, ';'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line), "\\"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		var name, version string
		if i := strings.Index(line, "==="); i >= 0 {
			name, version = line[:i], line[i+3:]
		} else if i := strings.Index(line, "=="); i >= 0 {
			name, version = line[:i], line[i+2:]
		} else {
			continue
		}
		if i := strings.IndexByte(name, '['); i >= 0 {
			name = name[:i]
		}
		name, version = strings.TrimSpace(name), strings.TrimSpace(version)
		if name == "" || version == "" || strings.ContainsAny(version, "*, <>!~ ") {
			continue
		}
		pn := strings.ToLower(strings.ReplaceAll(name, "_", "-"))
		out = append(out, Dependency{Name: name, Version: version, Purl: "pkg:pypi/" + pn + "@" + version})
	}
	return out, nil
}

func parseGoMod(data []byte) ([]Dependency, error) {
	var out []Dependency
	inBlock := false
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		switch {
		case len(f) == 0:
		case inBlock && f[0] == ")":
			inBlock = false
		case f[0] == "require" && len(f) == 2 && f[1] == "(":
			inBlock = true
		case f[0] == "require" && len(f) >= 3:
			out = appendGo(out, f[1], f[2])
		case inBlock && len(f) >= 2:
			out = appendGo(out, f[0], f[1])
		}
	}
	return out, nil
}

func appendGo(out []Dependency, mod, version string) []Dependency {
	if !strings.HasPrefix(version, "v") {
		return out
	}
	return append(out, Dependency{Name: mod, Version: version, Purl: "pkg:golang/" + mod + "@" + version})
}

type pomProject struct {
	Properties struct {
		Items []struct {
			XMLName xml.Name
			Value   string `xml:",chardata"`
		} `xml:",any"`
	} `xml:"properties"`
	Dependencies []struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
		Version    string `xml:"version"`
	} `xml:"dependencies>dependency"`
}

// parsePOM lists dependencies with a literal version, or a ${property}
// defined in the same pom. Ranges and inherited versions are skipped.
func parsePOM(data []byte) ([]Dependency, error) {
	var p pomProject
	if err := xml.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	props := map[string]string{}
	for _, it := range p.Properties.Items {
		props[it.XMLName.Local] = strings.TrimSpace(it.Value)
	}
	var out []Dependency
	for _, d := range p.Dependencies {
		v := strings.TrimSpace(d.Version)
		if strings.HasPrefix(v, "${") && strings.HasSuffix(v, "}") {
			v = props[v[2:len(v)-1]]
		}
		g, a := strings.TrimSpace(d.GroupID), strings.TrimSpace(d.ArtifactID)
		if g == "" || a == "" || v == "" || strings.ContainsAny(v, "[]()$,") {
			continue
		}
		out = append(out, Dependency{
			Name: g + ":" + a, Version: v,
			Purl: "pkg:maven/" + url.PathEscape(g) + "/" + url.PathEscape(a) + "@" + v,
		})
	}
	return out, nil
}
