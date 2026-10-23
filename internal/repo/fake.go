package repo

import (
	"context"
	"fmt"
)

// Fake is an in-memory Forge for tests: it resolves releases and serves
// tarball bytes from maps keyed by repo URL / tarball URL.
type Fake struct {
	ForgeName string
	Releases  map[string]*Release
	Tarballs  map[string][]byte
	Errors    map[string]error
}

// NewFake returns a Fake with no releases or tarballs configured.
func NewFake(name string) *Fake {
	return &Fake{
		ForgeName: name,
		Releases:  make(map[string]*Release),
		Tarballs:  make(map[string][]byte),
		Errors:    make(map[string]error),
	}
}

func (f *Fake) Name() string { return f.ForgeName }

func (f *Fake) LatestRelease(_ context.Context, repoURL string) (*Release, error) {
	if err, ok := f.Errors[repoURL]; ok {
		return nil, err
	}
	rel, ok := f.Releases[repoURL]
	if !ok {
		return nil, fmt.Errorf("repo: fake has no release configured for %q", repoURL)
	}
	return rel, nil
}

func (f *Fake) FetchTarball(_ context.Context, tarballURL string) ([]byte, error) {
	if err, ok := f.Errors[tarballURL]; ok {
		return nil, err
	}
	data, ok := f.Tarballs[tarballURL]
	if !ok {
		return nil, fmt.Errorf("repo: fake has no tarball configured for %q", tarballURL)
	}
	return data, nil
}
