package vuln

import "context"

// FakeSource is an in-memory Source for tests: it returns a fixed set of
// findings (or a fixed error) regardless of the queries it's given.
type FakeSource struct {
	SourceName string
	Findings   []Finding
	Err        error
}

func (f *FakeSource) Name() string { return f.SourceName }

func (f *FakeSource) Lookup(_ context.Context, _ []Query) ([]Finding, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	return f.Findings, nil
}

// FakeEnricher is an in-memory Enricher for tests: it returns canned
// enrichments keyed by finding id.
type FakeEnricher struct {
	EnricherName string
	Enrichments  map[string]Enrichment
	Err          error
}

func (f *FakeEnricher) Name() string { return f.EnricherName }

func (f *FakeEnricher) Enrich(_ context.Context, findingIDs []string) (map[string]Enrichment, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	out := make(map[string]Enrichment, len(findingIDs))
	for _, id := range findingIDs {
		if e, ok := f.Enrichments[id]; ok {
			out[id] = e
		}
	}
	return out, nil
}
