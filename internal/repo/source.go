package repo

import (
	"context"
	"fmt"

	"github.com/FootprintAI/touchstone/internal/pipeline"
)

// CaveatDefaultBranch marks components read from the default branch because
// the repo has no non-prerelease semver tag.
const CaveatDefaultBranch = "DEFAULT_BRANCH_NOT_RELEASE"

// Source is the pipeline.EvidenceSource for a repo: it resolves the latest
// release, fetches the tarball, and reports lockfile dependencies as
// Medium-confidence components.
type Source struct {
	// RepoURL is the repo to scan (user-supplied or discovered).
	RepoURL string
	// Forges are tried by host: "github.com" → "github", "gitlab.com" → "gitlab".
	Forges []Forge
}

func (s *Source) Name() string { return "repo" }

// Collect ignores targetURL: the repo is the source's own input. It returns
// ErrNoLockfile (wrapped) when the release has no supported lockfile.
func (s *Source) Collect(ctx context.Context, _ string) ([]pipeline.Component, error) {
	host, repoPath, err := ParseRepoURL(s.RepoURL)
	if err != nil {
		return nil, err
	}
	forge := s.forgeFor(host)
	if forge == nil {
		return nil, fmt.Errorf("repo: no forge for host %q", host)
	}
	rel, err := forge.LatestRelease(ctx, s.RepoURL)
	if err != nil {
		return nil, err
	}
	data, err := forge.FetchTarball(ctx, rel.TarballURL)
	if err != nil {
		return nil, err
	}
	deps, err := ExtractLockfiles(data)
	if err != nil {
		return nil, err
	}
	var caveats []string
	if rel.DefaultBranch {
		caveats = []string{CaveatDefaultBranch}
	}
	comps := make([]pipeline.Component, 0, len(deps))
	for _, d := range deps {
		loc := fmt.Sprintf("%s@%s:%s", repoPath, rel.Tag, d.Path)
		comps = append(comps, pipeline.Component{
			Name:       d.Name,
			Version:    d.Version,
			Purl:       d.Purl,
			Confidence: "MEDIUM",
			Evidence:   []pipeline.Evidence{{Kind: "LOCKFILE", Location: loc, Detail: "pinned in lockfile"}},
			Caveats:    caveats,
		})
	}
	return comps, nil
}

func (s *Source) forgeFor(host string) Forge {
	want := map[string]string{"github.com": "github", "gitlab.com": "gitlab"}[host]
	for _, f := range s.Forges {
		if f.Name() == want {
			return f
		}
	}
	return nil
}
