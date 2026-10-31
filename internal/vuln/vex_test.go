package vuln

import (
	"testing"

	"github.com/FootprintAI/touchstone/internal/sbom"
)

func TestApplyVEX(t *testing.T) {
	jq := sbom.Component{Name: "jquery", Version: "3.7.1", Purl: "pkg:npm/jquery@3.7.1"}
	queries := []Query{
		{Purl: "pkg:npm/jquery@3.7.1"},
		{Purl: "pkg:npm/lodash@4.17.21"},
		{CPE: "cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*"},
	}
	newResult := func() *Result {
		return &Result{Matches: [][]Match{
			{{Finding: Finding{ID: "CVE-2020-11022", Aliases: []string{"GHSA-gxr4-xjj5-5px2"}}},
				{Finding: Finding{ID: "CVE-2019-11358"}}},
			{{Finding: Finding{ID: "CVE-2021-23337"}}},
			{{Finding: Finding{ID: "CVE-2023-44487"}}},
		}}
	}
	tests := []struct {
		name       string
		stmts      []sbom.Statement
		query, idx int
		want       VEXInfo
	}{
		{"not_affected suppresses with justification",
			[]sbom.Statement{{Vulnerability: "CVE-2020-11022", Products: []sbom.Component{jq}, Status: sbom.VEXNotAffected, Justification: "code_not_reachable"}},
			0, 0, VEXInfo{Status: sbom.VEXNotAffected, Justification: "code_not_reachable", Suppressed: true}},
		{"fixed suppresses",
			[]sbom.Statement{{Vulnerability: "CVE-2020-11022", Products: []sbom.Component{jq}, Status: sbom.VEXFixed}},
			0, 0, VEXInfo{Status: sbom.VEXFixed, Suppressed: true}},
		{"matches by alias, case-insensitively",
			[]sbom.Statement{{Vulnerability: "ghsa-gxr4-xjj5-5px2", Products: []sbom.Component{jq}, Status: sbom.VEXNotAffected}},
			0, 0, VEXInfo{Status: sbom.VEXNotAffected, Suppressed: true}},
		{"statement alias names the finding id",
			[]sbom.Statement{{Vulnerability: "GHSA-x", Aliases: []string{"CVE-2020-11022"}, Products: []sbom.Component{jq}, Status: sbom.VEXFixed}},
			0, 0, VEXInfo{Status: sbom.VEXFixed, Suppressed: true}},
		{"affected is recorded but not suppressed",
			[]sbom.Statement{{Vulnerability: "CVE-2020-11022", Products: []sbom.Component{jq}, Status: sbom.VEXAffected}},
			0, 0, VEXInfo{Status: sbom.VEXAffected}},
		{"under_investigation is not suppressed",
			[]sbom.Statement{{Vulnerability: "CVE-2020-11022", Products: []sbom.Component{jq}, Status: sbom.VEXUnderInvestigation}},
			0, 0, VEXInfo{Status: sbom.VEXUnderInvestigation}},
		{"other vulnerability untouched",
			[]sbom.Statement{{Vulnerability: "CVE-2020-11022", Products: []sbom.Component{jq}, Status: sbom.VEXNotAffected}},
			0, 1, VEXInfo{}},
		{"other product untouched",
			[]sbom.Statement{{Vulnerability: "CVE-2021-23337", Products: []sbom.Component{jq}, Status: sbom.VEXNotAffected}},
			1, 0, VEXInfo{}},
		{"other version untouched",
			[]sbom.Statement{{Vulnerability: "CVE-2020-11022", Products: []sbom.Component{{Purl: "pkg:npm/jquery@1.12.4"}}, Status: sbom.VEXNotAffected}},
			0, 0, VEXInfo{}},
		{"versionless purl covers every version",
			[]sbom.Statement{{Vulnerability: "CVE-2020-11022", Products: []sbom.Component{{Purl: "pkg:npm/jquery"}}, Status: sbom.VEXNotAffected}},
			0, 0, VEXInfo{Status: sbom.VEXNotAffected, Suppressed: true}},
		{"purl qualifiers are ignored",
			[]sbom.Statement{{Vulnerability: "CVE-2020-11022", Products: []sbom.Component{{Purl: "pkg:npm/jquery@3.7.1?arch=x"}}, Status: sbom.VEXNotAffected}},
			0, 0, VEXInfo{Status: sbom.VEXNotAffected, Suppressed: true}},
		{"CPE product",
			[]sbom.Statement{{Vulnerability: "CVE-2023-44487", Products: []sbom.Component{{CPE: "cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*"}}, Status: sbom.VEXNotAffected}},
			2, 0, VEXInfo{Status: sbom.VEXNotAffected, Suppressed: true}},
		{"name-only product never matches",
			[]sbom.Statement{{Vulnerability: "CVE-2020-11022", Products: []sbom.Component{{Name: "jquery"}}, Status: sbom.VEXNotAffected}},
			0, 0, VEXInfo{}},
		{"last statement wins",
			[]sbom.Statement{
				{Vulnerability: "CVE-2020-11022", Products: []sbom.Component{jq}, Status: sbom.VEXNotAffected},
				{Vulnerability: "CVE-2020-11022", Products: []sbom.Component{jq}, Status: sbom.VEXAffected},
			},
			0, 0, VEXInfo{Status: sbom.VEXAffected}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := newResult()
			ApplyVEX(queries, res, tt.stmts)
			if got := res.Matches[tt.query][tt.idx].VEX; got != tt.want {
				t.Errorf("VEX = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestCountActiveDropsSuppressed(t *testing.T) {
	res := &Result{Matches: [][]Match{{
		{Finding: Finding{ID: "CVE-1"}},
		{Finding: Finding{ID: "CVE-2"}},
		{Finding: Finding{ID: "CVE-3"}},
	}}}
	ApplyVEX([]Query{{Purl: "pkg:npm/a@1"}}, res, []sbom.Statement{
		{Vulnerability: "CVE-1", Products: []sbom.Component{{Purl: "pkg:npm/a@1"}}, Status: sbom.VEXNotAffected},
		{Vulnerability: "CVE-2", Products: []sbom.Component{{Purl: "pkg:npm/a@1"}}, Status: sbom.VEXFixed},
	})
	if got := CountActive(res.Matches[0]); got != 1 {
		t.Errorf("CountActive = %d, want 1", got)
	}
}
