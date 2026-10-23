// Package pipeline defines the EvidenceSource seam that the pure merge
// core (see docs/architecture/touchstone.md) will orchestrate: discover,
// repo, fingerprint and supplied each implement it. The merge core itself
// lands in slice S2; this package only fixes the interface so S0 callers
// and their tests can be written against it now.
package pipeline

import "context"

// Evidence is why a Component was reported, independent of the proto
// representation: location is a URL, or repo@ref:path for lockfiles.
type Evidence struct {
	Kind     string
	Location string
	Detail   string
}

// Component is one piece of software an EvidenceSource found. Confidence
// reflects the source's tier (e.g. "HIGH" for a declared SBOM, "LOW" for a
// fingerprint match); pipeline's merge step resolves conflicts across
// sources.
type Component struct {
	Name       string
	Version    string
	Purl       string
	CPE        string
	Confidence string
	Evidence   []Evidence
	Caveats    []string
}

// EvidenceSource collects components for a scan target. One source
// failing must never fail the whole scan: pipeline records a
// SourceStatus and continues with the others.
type EvidenceSource interface {
	Name() string
	Collect(ctx context.Context, targetURL string) ([]Component, error)
}
