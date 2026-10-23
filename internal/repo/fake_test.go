package repo

import (
	"context"
	"testing"
)

func TestFakeResolvesConfiguredRelease(t *testing.T) {
	f := NewFake("github")
	want := &Release{Tag: "v1.2.0", TarballURL: "https://github.com/example/repo/archive/v1.2.0.tar.gz"}
	f.Releases["https://github.com/example/repo"] = want

	got, err := f.LatestRelease(context.Background(), "https://github.com/example/repo")
	if err != nil {
		t.Fatalf("LatestRelease: unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("LatestRelease: got %+v, want %+v", got, want)
	}
}

func TestFakeUnconfiguredRepoErrors(t *testing.T) {
	f := NewFake("github")
	if _, err := f.LatestRelease(context.Background(), "https://github.com/unknown/repo"); err == nil {
		t.Fatal("LatestRelease: want error for unconfigured repo, got nil")
	}
}

func TestFakeFetchesConfiguredTarball(t *testing.T) {
	f := NewFake("github")
	want := []byte("tarball-bytes")
	f.Tarballs["https://example.com/a.tar.gz"] = want

	got, err := f.FetchTarball(context.Background(), "https://example.com/a.tar.gz")
	if err != nil {
		t.Fatalf("FetchTarball: unexpected error: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("FetchTarball: got %q, want %q", got, want)
	}
}
