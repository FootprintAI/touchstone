package vuln

import (
	"strings"

	"github.com/FootprintAI/touchstone/internal/sbom"
)

// VEXInfo is what a VEX statement says about one match. The zero value
// means no statement applies.
type VEXInfo struct {
	Status        sbom.VEXStatus
	Justification string
	// Suppressed is true for NOT_AFFECTED and FIXED: the match is kept for
	// the report but does not count as a vulnerability.
	Suppressed bool
}

// ApplyVEX records on each match the VEX statement that applies to it:
// the statement must name the match's id or one of its aliases, and a
// product that is the match's query (same purl, ignoring qualifiers, or a
// versionless purl for the same package; or the same CPE). When several
// statements apply, the last in document order wins. not_affected and
// fixed suppress the match; affected and under_investigation are recorded
// but leave it counted. queries[i] is the query behind res.Matches[i].
func ApplyVEX(queries []Query, res *Result, stmts []sbom.Statement) {
	if len(stmts) == 0 {
		return
	}
	for i, ms := range res.Matches {
		if i >= len(queries) {
			break
		}
		for j := range ms {
			for _, st := range stmts {
				if statementApplies(st, queries[i], ms[j].Finding) {
					ms[j].VEX = VEXInfo{
						Status:        st.Status,
						Justification: st.Justification,
						Suppressed:    st.Status == sbom.VEXNotAffected || st.Status == sbom.VEXFixed,
					}
				}
			}
		}
	}
}

// CountActive returns how many matches are not suppressed by VEX: the
// number to show as a component's vulnerability count.
func CountActive(ms []Match) int {
	n := 0
	for _, m := range ms {
		if !m.VEX.Suppressed {
			n++
		}
	}
	return n
}

func statementApplies(st sbom.Statement, q Query, f Finding) bool {
	if !namesVulnerability(st, f) {
		return false
	}
	for _, p := range st.Products {
		if productIsQuery(p, q) {
			return true
		}
	}
	return false
}

func namesVulnerability(st sbom.Statement, f Finding) bool {
	ids := append([]string{f.ID}, f.Aliases...)
	for _, id := range ids {
		if id == "" {
			continue
		}
		if strings.EqualFold(id, st.Vulnerability) {
			return true
		}
		for _, a := range st.Aliases {
			if strings.EqualFold(id, a) {
				return true
			}
		}
	}
	return false
}

func productIsQuery(p sbom.Component, q Query) bool {
	if p.Purl != "" && q.Purl != "" {
		want, have := trimPurl(p.Purl), trimPurl(q.Purl)
		if want == have {
			return true
		}
		// A purl without a version names every version of the package.
		return !purlHasVersion(want) && want == stripPurlVersion(have)
	}
	return p.CPE != "" && q.CPE != "" && strings.EqualFold(p.CPE, q.CPE)
}

// trimPurl drops the qualifiers and subpath of a package URL.
func trimPurl(purl string) string {
	if i := strings.IndexAny(purl, "?#"); i >= 0 {
		return purl[:i]
	}
	return purl
}

func purlHasVersion(purl string) bool {
	return strings.LastIndex(purl, "@") > strings.LastIndex(purl, "/")
}

func stripPurlVersion(purl string) string {
	if purlHasVersion(purl) {
		return purl[:strings.LastIndex(purl, "@")]
	}
	return purl
}
