package repo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// maxTarballBytes caps a downloaded tarball; the repo is untrusted input.
const maxTarballBytes = 200 << 20

// maxAPIBytes caps a forge API JSON response.
const maxAPIBytes = 8 << 20

// ParseRepoURL returns the host and the "owner/name" path (GitLab allows
// nested groups) of a repo URL.
func ParseRepoURL(repoURL string) (host, path string, err error) {
	u, err := url.Parse(repoURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", "", fmt.Errorf("repo: %q is not an http(s) repo URL", repoURL)
	}
	var segs []string
	for _, s := range strings.Split(strings.Trim(u.Path, "/"), "/") {
		if s == "-" {
			break
		}
		segs = append(segs, s)
	}
	host = strings.ToLower(u.Hostname())
	if host == "github.com" && len(segs) > 2 {
		segs = segs[:2]
	}
	if len(segs) < 2 {
		return "", "", fmt.Errorf("repo: %q has no owner/name path", repoURL)
	}
	segs[len(segs)-1] = strings.TrimSuffix(segs[len(segs)-1], ".git")
	return host, strings.Join(segs, "/"), nil
}

// client is the HTTP plumbing shared by the forges. The token header is
// dropped on a redirect to another host (Go strips only Authorization).
type client struct {
	api       string
	tokenHdr  string
	tokenVal  string
	http      *http.Client
	userAgent string
}

func newClient(api, tokenHdr, tokenVal string, hc *http.Client) *client {
	c := &client{api: strings.TrimRight(api, "/"), tokenHdr: tokenHdr, tokenVal: tokenVal, userAgent: "touchstone"}
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	cp := *hc
	cp.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("repo: too many redirects")
		}
		if req.URL.Host != via[0].URL.Host {
			req.Header.Del(tokenHdr)
		}
		return nil
	}
	c.http = &cp
	return c
}

func (c *client) get(ctx context.Context, rawURL string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	if c.tokenVal != "" {
		if c.tokenHdr == "Authorization" {
			req.Header.Set("Authorization", "Bearer "+c.tokenVal)
		} else {
			req.Header.Set(c.tokenHdr, c.tokenVal)
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("repo: GET %s: %s", rawURL, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("repo: GET %s: response larger than %d bytes", rawURL, limit)
	}
	return data, nil
}

func (c *client) getJSON(ctx context.Context, rawURL string, out any) error {
	data, err := c.get(ctx, rawURL, maxAPIBytes)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

// fetchTarball only follows URLs the forge itself produced, so a caller
// cannot make the forge client (and its token) talk to another host.
func (c *client) fetchTarball(ctx context.Context, tarballURL string) ([]byte, error) {
	if !strings.HasPrefix(tarballURL, c.api+"/") {
		return nil, fmt.Errorf("repo: refusing tarball URL outside %s", c.api)
	}
	return c.get(ctx, tarballURL, maxTarballBytes)
}

// pickRelease turns a tag list into a Release, falling back to the default
// branch when no non-prerelease semver tag exists.
func pickRelease(tags []string, defaultBranch func() (string, error), tarball func(ref string) string) (*Release, error) {
	if tag, ok := LatestSemverTag(tags); ok {
		return &Release{Tag: tag, TarballURL: tarball(tag)}, nil
	}
	branch, err := defaultBranch()
	if err != nil {
		return nil, err
	}
	if branch == "" {
		return nil, fmt.Errorf("repo: no release tag and no default branch")
	}
	return &Release{Tag: branch, TarballURL: tarball(branch), DefaultBranch: true}, nil
}

// GitHub is the Forge for github.com. Token (GITHUB_TOKEN) is optional.
type GitHub struct{ c *client }

// NewGitHub returns a GitHub Forge. api is the API base ("" means
// https://api.github.com); token "" falls back to $GITHUB_TOKEN.
func NewGitHub(api, token string, hc *http.Client) *GitHub {
	if api == "" {
		api = "https://api.github.com"
	}
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	return &GitHub{c: newClient(api, "Authorization", token, hc)}
}

func (g *GitHub) Name() string { return "github" }

func (g *GitHub) LatestRelease(ctx context.Context, repoURL string) (*Release, error) {
	_, path, err := ParseRepoURL(repoURL)
	if err != nil {
		return nil, err
	}
	base := g.c.api + "/repos/" + path
	var tags []struct {
		Name string `json:"name"`
	}
	if err := g.c.getJSON(ctx, base+"/tags?per_page=100", &tags); err != nil {
		return nil, err
	}
	names := make([]string, len(tags))
	for i, t := range tags {
		names[i] = t.Name
	}
	return pickRelease(names, func() (string, error) {
		var r struct {
			DefaultBranch string `json:"default_branch"`
		}
		err := g.c.getJSON(ctx, base, &r)
		return r.DefaultBranch, err
	}, func(ref string) string { return base + "/tarball/" + url.PathEscape(ref) })
}

func (g *GitHub) FetchTarball(ctx context.Context, tarballURL string) ([]byte, error) {
	return g.c.fetchTarball(ctx, tarballURL)
}

// GitLab is the Forge for gitlab.com. Token (GITLAB_TOKEN) is optional.
type GitLab struct{ c *client }

// NewGitLab returns a GitLab Forge. api is the API base ("" means
// https://gitlab.com/api/v4); token "" falls back to $GITLAB_TOKEN.
func NewGitLab(api, token string, hc *http.Client) *GitLab {
	if api == "" {
		api = "https://gitlab.com/api/v4"
	}
	if token == "" {
		token = os.Getenv("GITLAB_TOKEN")
	}
	return &GitLab{c: newClient(api, "PRIVATE-TOKEN", token, hc)}
}

func (g *GitLab) Name() string { return "gitlab" }

func (g *GitLab) LatestRelease(ctx context.Context, repoURL string) (*Release, error) {
	_, path, err := ParseRepoURL(repoURL)
	if err != nil {
		return nil, err
	}
	base := g.c.api + "/projects/" + url.PathEscape(path)
	var tags []struct {
		Name string `json:"name"`
	}
	if err := g.c.getJSON(ctx, base+"/repository/tags?per_page=100", &tags); err != nil {
		return nil, err
	}
	names := make([]string, len(tags))
	for i, t := range tags {
		names[i] = t.Name
	}
	return pickRelease(names, func() (string, error) {
		var r struct {
			DefaultBranch string `json:"default_branch"`
		}
		err := g.c.getJSON(ctx, base, &r)
		return r.DefaultBranch, err
	}, func(ref string) string {
		return base + "/repository/archive.tar.gz?sha=" + url.QueryEscape(ref)
	})
}

func (g *GitLab) FetchTarball(ctx context.Context, tarballURL string) ([]byte, error) {
	return g.c.fetchTarball(ctx, tarballURL)
}
