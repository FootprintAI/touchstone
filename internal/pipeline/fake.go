package pipeline

import "context"

// FakeEvidenceSource is an in-memory EvidenceSource for tests: it returns
// a fixed set of components (or a fixed error) regardless of target.
type FakeEvidenceSource struct {
	SourceName string
	Components []Component
	Err        error
}

func (f *FakeEvidenceSource) Name() string { return f.SourceName }

func (f *FakeEvidenceSource) Collect(_ context.Context, _ string) ([]Component, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	return f.Components, nil
}
