package sbom

import (
	"encoding/json"
	"strings"
)

// VEXStatus is a VEX statement's claim about a product and a vulnerability,
// normalized across OpenVEX, CycloneDX and CSAF.
type VEXStatus string

const (
	VEXAffected           VEXStatus = "affected"
	VEXNotAffected        VEXStatus = "not_affected"
	VEXFixed              VEXStatus = "fixed"
	VEXUnderInvestigation VEXStatus = "under_investigation"
)

// Statement is one VEX claim: Status holds for Vulnerability (or one of its
// Aliases) in each of Products. Justification is the document's free-text
// or enumerated reason, empty when it gave none.
type Statement struct {
	Vulnerability string
	Aliases       []string
	Products      []Component
	Status        VEXStatus
	Justification string
}

// joinReason joins the non-empty parts of a justification with ": ".
func joinReason(parts ...string) string {
	var kept []string
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, ": ")
}

// OpenVEX

type openVEXStatement struct {
	Vulnerability   openVEXVuln      `json:"vulnerability"`
	Products        []openVEXProduct `json:"products"`
	Status          string           `json:"status"`
	Justification   string           `json:"justification"`
	ImpactStatement string           `json:"impact_statement"`
}

type openVEXProduct struct {
	ID          string `json:"@id"`
	Identifiers struct {
		Purl  string `json:"purl"`
		CPE23 string `json:"cpe23"`
	} `json:"identifiers"`
}

func (p openVEXProduct) component() Component {
	c := Component{Purl: p.Identifiers.Purl, CPE: p.Identifiers.CPE23}
	if c.Purl == "" && strings.HasPrefix(p.ID, "pkg:") {
		c.Purl = p.ID
	}
	if c.Purl == "" && c.CPE == "" {
		c.Name = p.ID
	}
	return c
}

// openVEXVuln is a vulnerability reference: an object in OpenVEX 0.2, a
// bare string in 0.0.x documents.
type openVEXVuln struct {
	Name    string   `json:"name"`
	Aliases []string `json:"aliases"`
}

func (v *openVEXVuln) UnmarshalJSON(data []byte) error {
	var s string
	if json.Unmarshal(data, &s) == nil {
		v.Name = s
		return nil
	}
	type plain openVEXVuln
	return json.Unmarshal(data, (*plain)(v))
}

func openVEXStatements(in []openVEXStatement) []Statement {
	var out []Statement
	for _, s := range in {
		status, ok := vexStatus(s.Status)
		if !ok || s.Vulnerability.Name == "" {
			continue
		}
		st := Statement{
			Vulnerability: s.Vulnerability.Name,
			Aliases:       s.Vulnerability.Aliases,
			Status:        status,
			Justification: joinReason(s.Justification, s.ImpactStatement),
		}
		for _, p := range s.Products {
			if c := normalize(p.component()); c != (Component{}) {
				st.Products = append(st.Products, c)
			}
		}
		out = append(out, st)
	}
	return out
}

func vexStatus(s string) (VEXStatus, bool) {
	switch VEXStatus(s) {
	case VEXAffected, VEXNotAffected, VEXFixed, VEXUnderInvestigation:
		return VEXStatus(s), true
	}
	return "", false
}

// CycloneDX

type cdxVuln struct {
	ID         string `json:"id"`
	References []struct {
		ID string `json:"id"`
	} `json:"references"`
	Analysis struct {
		State         string `json:"state"`
		Justification string `json:"justification"`
		Detail        string `json:"detail"`
	} `json:"analysis"`
	Affects []struct {
		Ref string `json:"ref"`
	} `json:"affects"`
}

// cdxStatements maps CycloneDX analysis states to VEX statuses. refs maps
// bom-ref to the component it names; an affects ref that is not a bom-ref
// but is a purl names that package.
func cdxStatements(vulns []cdxVuln, refs map[string]Component) []Statement {
	var out []Statement
	for _, v := range vulns {
		var status VEXStatus
		switch v.Analysis.State {
		case "not_affected", "false_positive":
			status = VEXNotAffected
		case "resolved", "resolved_with_pedigree":
			status = VEXFixed
		case "exploitable":
			status = VEXAffected
		case "in_triage":
			status = VEXUnderInvestigation
		default:
			continue
		}
		if v.ID == "" {
			continue
		}
		st := Statement{
			Vulnerability: v.ID,
			Status:        status,
			Justification: joinReason(v.Analysis.Justification, v.Analysis.Detail),
		}
		for _, r := range v.References {
			if r.ID != "" && r.ID != v.ID {
				st.Aliases = append(st.Aliases, r.ID)
			}
		}
		for _, a := range v.Affects {
			if c, ok := refs[a.Ref]; ok {
				st.Products = append(st.Products, c)
			} else if strings.HasPrefix(a.Ref, "pkg:") {
				st.Products = append(st.Products, normalize(Component{Purl: a.Ref}))
			}
		}
		out = append(out, st)
	}
	return out
}

// CSAF

type csafVuln struct {
	CVE string `json:"cve"`
	IDs []struct {
		Text string `json:"text"`
	} `json:"ids"`
	ProductStatus struct {
		KnownNotAffected   []string `json:"known_not_affected"`
		Fixed              []string `json:"fixed"`
		FirstFixed         []string `json:"first_fixed"`
		KnownAffected      []string `json:"known_affected"`
		UnderInvestigation []string `json:"under_investigation"`
	} `json:"product_status"`
	Flags []struct {
		Label      string   `json:"label"`
		ProductIDs []string `json:"product_ids"`
	} `json:"flags"`
	Threats []struct {
		Category   string   `json:"category"`
		Details    string   `json:"details"`
		ProductIDs []string `json:"product_ids"`
	} `json:"threats"`
}

// csafStatements makes one statement per product_status group. products
// maps product_id to the component it names. The justification of a
// not-affected group is the flag labels and impact threat details that
// name any of its products.
func csafStatements(vulns []csafVuln, products map[string]Component) []Statement {
	var out []Statement
	for _, v := range vulns {
		id := v.CVE
		var aliases []string
		for _, x := range v.IDs {
			switch {
			case x.Text == "" || x.Text == id:
			case id == "":
				id = x.Text
			default:
				aliases = append(aliases, x.Text)
			}
		}
		if id == "" {
			continue
		}
		groups := []struct {
			status VEXStatus
			ids    []string
		}{
			{VEXNotAffected, v.ProductStatus.KnownNotAffected},
			{VEXFixed, append(append([]string{}, v.ProductStatus.Fixed...), v.ProductStatus.FirstFixed...)},
			{VEXAffected, v.ProductStatus.KnownAffected},
			{VEXUnderInvestigation, v.ProductStatus.UnderInvestigation},
		}
		for _, g := range groups {
			if len(g.ids) == 0 {
				continue
			}
			st := Statement{Vulnerability: id, Aliases: aliases, Status: g.status}
			for _, pid := range g.ids {
				if c, ok := products[pid]; ok {
					st.Products = append(st.Products, c)
				}
			}
			if g.status == VEXNotAffected {
				var reasons []string
				for _, f := range v.Flags {
					if intersects(f.ProductIDs, g.ids) {
						reasons = append(reasons, f.Label)
					}
				}
				for _, t := range v.Threats {
					if t.Category == "impact" && intersects(t.ProductIDs, g.ids) {
						reasons = append(reasons, t.Details)
					}
				}
				st.Justification = joinReason(reasons...)
			}
			out = append(out, st)
		}
	}
	return out
}

func intersects(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}
