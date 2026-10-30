package vuln

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func f64(v float64) *float64 { return &v }

func TestRank(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []Match
		want []string
	}{
		{
			name: "KEV first even with a lower EPSS",
			in: []Match{
				{Finding: Finding{ID: "A"}, Enrichment: Enrichment{EPSS: f64(0.9)}},
				{Finding: Finding{ID: "B"}, Enrichment: Enrichment{KEV: true, EPSS: f64(0.01)}},
			},
			want: []string{"B", "A"},
		},
		{
			name: "EPSS descending",
			in: []Match{
				{Finding: Finding{ID: "A"}, Enrichment: Enrichment{EPSS: f64(0.1)}},
				{Finding: Finding{ID: "B"}, Enrichment: Enrichment{EPSS: f64(0.5)}},
				{Finding: Finding{ID: "C"}, Enrichment: Enrichment{EPSS: f64(0.3)}},
			},
			want: []string{"B", "C", "A"},
		},
		{
			name: "missing EPSS sorts last even with a high CVSS",
			in: []Match{
				{Finding: Finding{ID: "A", CVSSBase: f64(9.8)}},
				{Finding: Finding{ID: "B", CVSSBase: f64(2.0)}, Enrichment: Enrichment{EPSS: f64(0.0001)}},
			},
			want: []string{"B", "A"},
		},
		{
			name: "CVSS breaks EPSS ties, missing CVSS last",
			in: []Match{
				{Finding: Finding{ID: "A"}, Enrichment: Enrichment{EPSS: f64(0.2)}},
				{Finding: Finding{ID: "B", CVSSBase: f64(5.0)}, Enrichment: Enrichment{EPSS: f64(0.2)}},
				{Finding: Finding{ID: "C", CVSSBase: f64(7.5)}, Enrichment: Enrichment{EPSS: f64(0.2)}},
			},
			want: []string{"C", "B", "A"},
		},
		{
			name: "missing EPSS ordered by CVSS",
			in: []Match{
				{Finding: Finding{ID: "A", CVSSBase: f64(4.0)}},
				{Finding: Finding{ID: "B", CVSSBase: f64(8.0)}},
			},
			want: []string{"B", "A"},
		},
		{
			name: "full ties by id",
			in: []Match{
				{Finding: Finding{ID: "CVE-2"}},
				{Finding: Finding{ID: "CVE-1"}},
			},
			want: []string{"CVE-1", "CVE-2"},
		},
		{
			name: "KEV group ranked by EPSS within itself",
			in: []Match{
				{Finding: Finding{ID: "A"}, Enrichment: Enrichment{KEV: true}},
				{Finding: Finding{ID: "B"}, Enrichment: Enrichment{EPSS: f64(0.99)}},
				{Finding: Finding{ID: "C"}, Enrichment: Enrichment{KEV: true, EPSS: f64(0.4)}},
			},
			want: []string{"C", "A", "B"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			Rank(tc.in)
			var got []string
			for _, m := range tc.in {
				got = append(got, m.ID)
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("Rank = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLookupStatus(t *testing.T) {
	down := errors.New("down")
	osvOK := &FakeSource{SourceName: "OSV", Findings: []Finding{{ID: "CVE-1"}}}
	osvDown := &FakeSource{SourceName: "OSV", Err: down}
	nvdOK := &FakeSource{SourceName: "NVD", Findings: []Finding{{ID: "CVE-2"}}}
	nvdDown := &FakeSource{SourceName: "NVD", Err: down}
	kevOK := &FakeEnricher{EnricherName: "KEV"}
	kevDown := &FakeEnricher{EnricherName: "KEV", Err: down}
	both := []Query{{Purl: "pkg:npm/a@1"}, {CPE: "cpe:2.3:a:b:b:1:*:*:*:*:*:*:*"}}

	for _, tc := range []struct {
		name    string
		m       Matcher
		queries []Query
		want    Status
	}{
		{"all succeed", Matcher{Purl: osvOK, CPE: nvdOK, Enrichers: []Enricher{kevOK}}, both, StatusComplete},
		{"nothing to look up", Matcher{Purl: osvOK, CPE: nvdOK}, nil, StatusComplete},
		{"OSV down, NVD up", Matcher{Purl: osvDown, CPE: nvdOK}, both, StatusPartial},
		{"NVD down, OSV up", Matcher{Purl: osvOK, CPE: nvdDown}, both, StatusPartial},
		{"every source down", Matcher{Purl: osvDown, CPE: nvdDown}, both, StatusFailed},
		{"only source down", Matcher{Purl: osvDown}, both[:1], StatusFailed},
		{"enricher down", Matcher{Purl: osvOK, CPE: nvdOK, Enrichers: []Enricher{kevDown}}, both, StatusPartial},
		{"CPE cap skips a lookup", Matcher{Purl: osvOK, CPE: nvdOK, CPELimit: 1},
			append(both, Query{CPE: "cpe:2.3:a:c:c:1:*:*:*:*:*:*:*"}), StatusPartial},
		{"CPE cap with only CPE queries", Matcher{CPE: nvdOK, CPELimit: 1},
			[]Query{{CPE: "cpe:2.3:a:b:b:1:*:*:*:*:*:*:*"}, {CPE: "cpe:2.3:a:c:c:1:*:*:*:*:*:*:*"}}, StatusPartial},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := tc.m.Match(context.Background(), tc.queries)
			if res.Status != tc.want {
				t.Errorf("Status = %v, want %v (sources %+v)", res.Status, tc.want, res.Sources)
			}
			if res.Status != StatusComplete {
				failed := false
				for _, s := range res.Sources {
					if !s.OK && s.Error != "" {
						failed = true
					}
				}
				if !failed {
					t.Errorf("Status %v but no SourceStatus carries an error: %+v", res.Status, res.Sources)
				}
			}
		})
	}
}

func TestMatcherRoutesQueriesAndEnriches(t *testing.T) {
	m := Matcher{
		Purl: &FakeSource{SourceName: "OSV", Findings: []Finding{{ID: "CVE-1", CVSSBase: f64(9.0)}, {ID: "CVE-2"}}},
		CPE:  &FakeSource{SourceName: "NVD", Findings: []Finding{{ID: "CVE-3"}}},
		Enrichers: []Enricher{
			&FakeEnricher{EnricherName: "KEV", Enrichments: map[string]Enrichment{"CVE-2": {KEV: true}}},
			&FakeEnricher{EnricherName: "EPSS", Enrichments: map[string]Enrichment{"CVE-2": {EPSS: f64(0.3)}, "CVE-3": {EPSS: f64(0.1)}}},
		},
	}
	res := m.Match(context.Background(), []Query{
		{Purl: "pkg:npm/a@1", CPE: "cpe:2.3:a:a:a:1:*:*:*:*:*:*:*"},
		{CPE: "cpe:2.3:a:b:b:1:*:*:*:*:*:*:*"},
		{},
	})
	if res.Status != StatusComplete {
		t.Fatalf("Status = %v, want complete: %+v", res.Status, res.Sources)
	}
	if len(res.Matches) != 3 || len(res.Matches[0]) != 2 || len(res.Matches[1]) != 1 || len(res.Matches[2]) != 0 {
		t.Fatalf("Matches = %+v; want OSV's two, NVD's one, nothing for the empty query", res.Matches)
	}
	top := res.Matches[0][0]
	if top.ID != "CVE-2" || !top.KEV || top.EPSS == nil || *top.EPSS != 0.3 {
		t.Errorf("top match = %+v, want CVE-2 with KEV and EPSS 0.3", top)
	}
	if e := res.Matches[1][0].EPSS; e == nil || *e != 0.1 {
		t.Errorf("NVD match epss = %v, want 0.1", e)
	}
	var names []string
	for _, s := range res.Sources {
		names = append(names, s.Source)
	}
	if strings.Join(names, ",") != "OSV,NVD,KEV,EPSS" {
		t.Errorf("sources = %v, want OSV,NVD,KEV,EPSS", names)
	}
}

func TestMatcherReportsCPECap(t *testing.T) {
	m := Matcher{CPE: &FakeSource{SourceName: "NVD"}, CPELimit: 2}
	var qs []Query
	for _, p := range []string{"a", "b", "c", "d"} {
		qs = append(qs, Query{CPE: "cpe:2.3:a:" + p + ":" + p + ":1:*:*:*:*:*:*:*"})
	}
	res := m.Match(context.Background(), qs)
	if len(res.Sources) != 1 {
		t.Fatalf("sources = %+v, want the NVD status", res.Sources)
	}
	s := res.Sources[0]
	if s.OK || !strings.Contains(s.Error, "2 CPE lookups skipped") || !strings.Contains(s.Error, "capped at 2") {
		t.Errorf("NVD status = %+v, want the cap and the skipped count reported", s)
	}
}
