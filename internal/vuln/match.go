package vuln

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Match is one finding with the enrichment attached to it.
type Match struct {
	Finding
	Enrichment
}

// Rank orders matches for display: KEV-listed first, then EPSS descending,
// then CVSS base descending. A missing EPSS or CVSS sorts after every
// present one; ties keep id order so the report is stable.
func Rank(ms []Match) {
	slices.SortStableFunc(ms, func(a, b Match) int {
		if a.KEV != b.KEV {
			if a.KEV {
				return -1
			}
			return 1
		}
		if c := descMissingLast(a.EPSS, b.EPSS); c != 0 {
			return c
		}
		if c := descMissingLast(a.CVSSBase, b.CVSSBase); c != 0 {
			return c
		}
		return cmp.Compare(a.ID, b.ID)
	})
}

func descMissingLast(a, b *float64) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return 1
	case b == nil:
		return -1
	default:
		return cmp.Compare(*b, *a)
	}
}

// Status is how complete a Matcher's answer is. Only StatusComplete may be
// shown as a vulnerability count.
type Status int

const (
	StatusComplete Status = iota + 1 // every lookup and enrichment succeeded
	StatusPartial                    // some lookups or an enrichment failed or were skipped
	StatusFailed                     // every lookup attempted failed or was skipped
)

// SourceStatus is one vulnerability source's or enricher's outcome.
type SourceStatus struct {
	Source string
	OK     bool
	Error  string
}

// Result is a Matcher's answer: Matches[i] holds the ranked matches for
// the i-th query.
type Result struct {
	Matches [][]Match
	Status  Status
	Sources []SourceStatus
}

// Matcher looks up a scan's components: purls in Purl (OSV), components
// with only a CPE in CPE (NVD), then enriches every finding (KEV, EPSS)
// and ranks each component's matches. A nil Purl or CPE source means that
// kind of query is not looked up.
type Matcher struct {
	Purl Source
	CPE  Source

	// CPELimit caps the CPE lookups in one scan; 0 is no cap. Queries
	// past the cap are skipped and reported in the CPE source's status.
	CPELimit  int
	Enrichers []Enricher
}

// sourceTally counts one source's outcomes within a Match call.
type sourceTally struct {
	ok, failed, skipped int
	errs                []error
}

// Match looks up every query. A source failing never stops the others; it
// is recorded in Sources and makes Status PARTIAL or FAILED.
func (m *Matcher) Match(ctx context.Context, queries []Query) Result {
	res := Result{Matches: make([][]Match, len(queries))}
	var purl, cpe sourceTally
	cpeTried := 0
	for i, q := range queries {
		var src Source
		var t *sourceTally
		switch {
		case q.Purl != "" && m.Purl != nil:
			src, t = m.Purl, &purl
		case q.Purl == "" && q.CPE != "" && m.CPE != nil:
			if m.CPELimit > 0 && cpeTried >= m.CPELimit {
				cpe.skipped++
				continue
			}
			cpeTried++
			src, t = m.CPE, &cpe
		default:
			continue
		}
		findings, err := src.Lookup(ctx, []Query{q})
		if err != nil {
			t.failed++
			t.errs = append(t.errs, err)
			continue
		}
		t.ok++
		for _, f := range findings {
			res.Matches[i] = append(res.Matches[i], Match{Finding: f})
		}
	}
	if m.Purl != nil {
		res.addSource(m.Purl.Name(), purl, 0)
	}
	if m.CPE != nil {
		res.addSource(m.CPE.Name(), cpe, m.CPELimit)
	}

	enrichFailed := m.enrich(ctx, &res)
	for _, ms := range res.Matches {
		Rank(ms)
	}

	ok := purl.ok + cpe.ok
	bad := purl.failed + purl.skipped + cpe.failed + cpe.skipped
	switch {
	case bad == 0 && !enrichFailed:
		res.Status = StatusComplete
	case bad > 0 && ok == 0:
		res.Status = StatusFailed
	default:
		res.Status = StatusPartial
	}
	return res
}

// addSource records a source's status if it was asked anything or had
// queries skipped by the cap.
func (r *Result) addSource(name string, t sourceTally, limit int) {
	if t.ok+t.failed+t.skipped == 0 {
		return
	}
	errs := t.errs
	if t.skipped > 0 {
		errs = append(errs, fmt.Errorf("%s: %d CPE lookups skipped: capped at %d per scan without an API key (set NVD_API_KEY)",
			strings.ToLower(name), t.skipped, limit))
	}
	r.Sources = append(r.Sources, SourceStatus{
		Source: name,
		OK:     t.failed+t.skipped == 0,
		Error:  errText(errors.Join(errs...)),
	})
}

// enrich runs every enricher over the distinct finding ids and merges
// their answers into the matches. It reports whether any enricher failed.
func (m *Matcher) enrich(ctx context.Context, res *Result) bool {
	var ids []string
	seen := map[string]bool{}
	for _, ms := range res.Matches {
		for _, x := range ms {
			if !seen[x.ID] {
				seen[x.ID] = true
				ids = append(ids, x.ID)
			}
		}
	}
	if len(ids) == 0 {
		return false
	}
	failed := false
	for _, e := range m.Enrichers {
		got, err := e.Enrich(ctx, ids)
		res.Sources = append(res.Sources, SourceStatus{Source: e.Name(), OK: err == nil, Error: errText(err)})
		if err != nil {
			failed = true
			continue
		}
		for _, ms := range res.Matches {
			for j := range ms {
				en, ok := got[ms[j].ID]
				if !ok {
					continue
				}
				ms[j].KEV = ms[j].KEV || en.KEV
				if ms[j].EPSS == nil {
					ms[j].EPSS = en.EPSS
				}
			}
		}
	}
	return failed
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return strings.TrimSpace(err.Error())
}
