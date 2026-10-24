package vuln

import (
	"reflect"
	"testing"
)

func ptr(f float64) *float64 { return &f }

func ids(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}

func TestRank(t *testing.T) {
	tests := []struct {
		name string
		in   []Finding
		want []string
	}{
		{
			name: "KEV first even with a lower EPSS",
			in: []Finding{
				{ID: "CVE-A", EPSS: ptr(0.9)},
				{ID: "CVE-B", KEV: true, EPSS: ptr(0.1)},
			},
			want: []string{"CVE-B", "CVE-A"},
		},
		{
			name: "EPSS descending within a KEV group",
			in: []Finding{
				{ID: "CVE-A", EPSS: ptr(0.2)},
				{ID: "CVE-B", EPSS: ptr(0.7)},
				{ID: "CVE-C", EPSS: ptr(0.4)},
			},
			want: []string{"CVE-B", "CVE-C", "CVE-A"},
		},
		{
			name: "missing EPSS sorts last, even above a low score and a high CVSS",
			in: []Finding{
				{ID: "CVE-A", CVSSBase: ptr(10)},
				{ID: "CVE-B", EPSS: ptr(0.01)},
				{ID: "CVE-C", EPSS: ptr(0.0)},
			},
			want: []string{"CVE-B", "CVE-C", "CVE-A"},
		},
		{
			name: "CVSS descending breaks EPSS ties, missing CVSS last",
			in: []Finding{
				{ID: "CVE-A", EPSS: ptr(0.5)},
				{ID: "CVE-B", EPSS: ptr(0.5), CVSSBase: ptr(4.3)},
				{ID: "CVE-C", EPSS: ptr(0.5), CVSSBase: ptr(9.8)},
			},
			want: []string{"CVE-C", "CVE-B", "CVE-A"},
		},
		{
			name: "missing EPSS and CVSS fall back to id",
			in: []Finding{
				{ID: "GHSA-b"},
				{ID: "CVE-z"},
				{ID: "GHSA-a"},
			},
			want: []string{"CVE-z", "GHSA-a", "GHSA-b"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Rank(tt.in)
			if got := ids(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Rank order = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestApplySetsKEVAndEPSSByID(t *testing.T) {
	fs := []Finding{{ID: "CVE-1"}, {ID: "CVE-2"}, {ID: "GHSA-x"}}
	kev := map[string]Enrichment{"CVE-1": {KEV: true}}
	epss := map[string]Enrichment{"CVE-1": {EPSS: ptr(0.3)}, "CVE-2": {EPSS: ptr(0.6)}}

	Apply(fs, kev, epss)

	if !fs[0].KEV || fs[0].EPSS == nil || *fs[0].EPSS != 0.3 {
		t.Errorf("CVE-1 = %+v, want KEV and EPSS 0.3", fs[0])
	}
	if fs[1].KEV || fs[1].EPSS == nil || *fs[1].EPSS != 0.6 {
		t.Errorf("CVE-2 = %+v, want no KEV and EPSS 0.6", fs[1])
	}
	if fs[2].KEV || fs[2].EPSS != nil {
		t.Errorf("GHSA-x = %+v, want no enrichment", fs[2])
	}
}
