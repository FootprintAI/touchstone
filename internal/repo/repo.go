// Package repo defines the Forge seam for resolving a public repo's
// latest release and fetching its tarball. Real implementations (GitHub,
// GitLab; see docs/architecture/touchstone.md) land in slice S6; this
// package only fixes the interface so S0 callers and their tests can be
// written against it now.
package repo

import "context"

// Release is a resolved repo release: the tag used as evidence location
// (repo@<tag>:<path>) and the tarball URL to fetch it from.
type Release struct {
	Tag        string
	TarballURL string
}

// Forge resolves a repo URL to its latest release and fetches release
// tarballs through the forge's API (never through fetch.Fetcher: forge
// calls don't count against the vendor's passive request budget).
type Forge interface {
	Name() string
	LatestRelease(ctx context.Context, repoURL string) (*Release, error)
	FetchTarball(ctx context.Context, tarballURL string) ([]byte, error)
}
