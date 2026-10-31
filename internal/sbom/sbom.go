// Package sbom reads SBOM and VEX documents into normalized components.
// It does no I/O. This is the minimal reader discovery (slice S5) needs:
// it detects the format and lists the components or products a document
// names. Full parsers with VEX statements and their application to
// vulnerabilities are slice S4.
package sbom

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Format names a supported document format.
type Format string

const (
	FormatCycloneDX Format = "CycloneDX"
	FormatSPDX      Format = "SPDX"
	FormatOpenVEX   Format = "OpenVEX"
	FormatCSAF      Format = "CSAF"
)

// ParseError is returned when a document is in a supported format but
// malformed or incomplete. Err says what is wrong.
type ParseError struct {
	Format Format
	Err    error
}

func (e *ParseError) Error() string { return fmt.Sprintf("sbom: %s: %v", e.Format, e.Err) }
func (e *ParseError) Unwrap() error { return e.Err }

// ErrUnknownFormat is returned for input that is not a JSON document in a
// supported format.
var ErrUnknownFormat = errors.New("sbom: not a CycloneDX, SPDX 2.3, OpenVEX or CSAF 2.0 JSON document")

// Component is one piece of software a document names.
type Component struct {
	Name    string
	Version string
	Purl    string
	CPE     string
}

// Document is a parsed SBOM or VEX document.
type Document struct {
	Format Format
	// VEX is true for OpenVEX, for CSAF with document.category csaf_vex,
	// and for CycloneDX carrying vulnerabilities (CycloneDX VEX).
	VEX        bool
	Components []Component
	// Statements are the VEX statements the document makes, in document
	// order. Empty for an SBOM without vulnerability analysis.
	Statements []Statement
}

// probe holds the fields that tell the formats apart.
type probe struct {
	BOMFormat   string          `json:"bomFormat"`
	SPDXVersion string          `json:"spdxVersion"`
	Context     string          `json:"@context"`
	Document    json.RawMessage `json:"document"`
}

// Parse detects the format of data and lists its components.
func Parse(data []byte) (*Document, error) {
	var p probe
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnknownFormat, err)
	}
	switch {
	case p.BOMFormat == "CycloneDX":
		return parseCycloneDX(data)
	case strings.HasPrefix(p.SPDXVersion, "SPDX-"):
		return parseSPDX(data)
	case strings.Contains(p.Context, "openvex"):
		return parseOpenVEX(data)
	case len(p.Document) > 0:
		return ParseCSAF(data)
	default:
		return nil, ErrUnknownFormat
	}
}

type cdxComponent struct {
	Name       string         `json:"name"`
	Group      string         `json:"group"`
	Version    string         `json:"version"`
	Purl       string         `json:"purl"`
	CPE        string         `json:"cpe"`
	BOMRef     string         `json:"bom-ref"`
	Components []cdxComponent `json:"components"`
}

type cdxBOM struct {
	Components      []cdxComponent `json:"components"`
	Vulnerabilities []cdxVuln      `json:"vulnerabilities"`
}

func parseCycloneDX(data []byte) (*Document, error) {
	var bom cdxBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, &ParseError{FormatCycloneDX, err}
	}
	doc := &Document{Format: FormatCycloneDX, VEX: len(bom.Vulnerabilities) > 0}
	refs := map[string]Component{}
	var walk func([]cdxComponent)
	walk = func(cs []cdxComponent) {
		for _, c := range cs {
			name := c.Name
			if c.Group != "" {
				name = c.Group + "/" + c.Name
			}
			comp := normalize(Component{Name: name, Version: c.Version, Purl: c.Purl, CPE: c.CPE})
			doc.add(comp)
			if c.BOMRef != "" {
				refs[c.BOMRef] = comp
			}
			walk(c.Components)
		}
	}
	walk(bom.Components)
	doc.Statements = cdxStatements(bom.Vulnerabilities, refs)
	return doc, nil
}

type spdxDocument struct {
	Packages []struct {
		Name         string `json:"name"`
		VersionInfo  string `json:"versionInfo"`
		ExternalRefs []struct {
			ReferenceType    string `json:"referenceType"`
			ReferenceLocator string `json:"referenceLocator"`
		} `json:"externalRefs"`
	} `json:"packages"`
}

func parseSPDX(data []byte) (*Document, error) {
	var sd spdxDocument
	if err := json.Unmarshal(data, &sd); err != nil {
		return nil, &ParseError{FormatSPDX, err}
	}
	doc := &Document{Format: FormatSPDX}
	for _, p := range sd.Packages {
		c := Component{Name: p.Name, Version: p.VersionInfo}
		for _, ref := range p.ExternalRefs {
			switch ref.ReferenceType {
			case "purl":
				c.Purl = ref.ReferenceLocator
			case "cpe23Type", "cpe22Type":
				if c.CPE == "" {
					c.CPE = ref.ReferenceLocator
				}
			}
		}
		doc.add(c)
	}
	return doc, nil
}

type openVEXDocument struct {
	Statements []openVEXStatement `json:"statements"`
}

func parseOpenVEX(data []byte) (*Document, error) {
	var vd openVEXDocument
	if err := json.Unmarshal(data, &vd); err != nil {
		return nil, &ParseError{FormatOpenVEX, err}
	}
	doc := &Document{Format: FormatOpenVEX, VEX: true}
	for _, s := range vd.Statements {
		for _, p := range s.Products {
			doc.add(p.component())
		}
	}
	doc.Statements = openVEXStatements(vd.Statements)
	return doc, nil
}

type csafDocument struct {
	Document struct {
		Category    string `json:"category"`
		CSAFVersion string `json:"csaf_version"`
	} `json:"document"`
	ProductTree struct {
		Branches         []csafBranch  `json:"branches"`
		FullProductNames []csafProduct `json:"full_product_names"`
	} `json:"product_tree"`
	Vulnerabilities []csafVuln `json:"vulnerabilities"`
}

type csafBranch struct {
	Category string       `json:"category"`
	Name     string       `json:"name"`
	Branches []csafBranch `json:"branches"`
	Product  *csafProduct `json:"product"`
}

type csafProduct struct {
	ProductID string `json:"product_id"`
	Name      string `json:"name"`
	Helper    struct {
		CPE  string `json:"cpe"`
		Purl string `json:"purl"`
	} `json:"product_identification_helper"`
}

// ParseCSAF reads a CSAF 2.0 document. Its components are the products in
// the product tree: the name and version come from the enclosing
// product_name and product_version branches when present, else from the
// product's purl, else from its full name.
func ParseCSAF(data []byte) (*Document, error) {
	var cd csafDocument
	if err := json.Unmarshal(data, &cd); err != nil {
		return nil, &ParseError{FormatCSAF, err}
	}
	if cd.Document.CSAFVersion == "" || cd.Document.Category == "" {
		return nil, &ParseError{FormatCSAF, errors.New("document.csaf_version and document.category are required")}
	}
	doc := &Document{Format: FormatCSAF, VEX: cd.Document.Category == "csaf_vex"}
	products := map[string]Component{}
	addProduct := func(p csafProduct, name, version string) {
		c := normalize(csafComponent(p, name, version))
		doc.add(c)
		if p.ProductID != "" {
			products[p.ProductID] = c
		}
	}
	var walk func(bs []csafBranch, name, version string)
	walk = func(bs []csafBranch, name, version string) {
		for _, b := range bs {
			n, v := name, version
			switch b.Category {
			case "product_name":
				n = b.Name
			case "product_version":
				v = b.Name
			}
			if b.Product != nil {
				addProduct(*b.Product, n, v)
			}
			walk(b.Branches, n, v)
		}
	}
	walk(cd.ProductTree.Branches, "", "")
	for _, p := range cd.ProductTree.FullProductNames {
		addProduct(p, "", "")
	}
	doc.Statements = csafStatements(cd.Vulnerabilities, products)
	return doc, nil
}

func csafComponent(p csafProduct, name, version string) Component {
	// A purl names the package better than the product's full name, which
	// usually includes the vendor and version; add fills it in.
	if name == "" && p.Helper.Purl == "" {
		name = p.Name
	}
	return Component{Name: name, Version: version, Purl: p.Helper.Purl, CPE: p.Helper.CPE}
}

// add appends c, filling the name and version from its purl when the
// document left them out, and skips a component that names nothing or
// repeats one already listed.
func (d *Document) add(c Component) {
	c = normalize(c)
	if c.Name == "" && c.Purl == "" && c.CPE == "" {
		return
	}
	for _, have := range d.Components {
		if have == c {
			return
		}
	}
	d.Components = append(d.Components, c)
}

// normalize fills a component's name and version from its purl when the
// document left them out.
func normalize(c Component) Component {
	if c.Purl != "" && (c.Name == "" || c.Version == "") {
		name, version := purlNameVersion(c.Purl)
		if c.Name == "" {
			c.Name = name
		}
		if c.Version == "" {
			c.Version = version
		}
	}
	return c
}

// purlNameVersion returns the name and version of a package URL,
// pkg:type/namespace/name@version?qualifiers#subpath.
func purlNameVersion(purl string) (name, version string) {
	rest := strings.TrimPrefix(purl, "pkg:")
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.LastIndex(rest, "@"); i >= 0 && i > strings.LastIndex(rest, "/") {
		version, rest = rest[i+1:], rest[:i]
	}
	if i := strings.LastIndex(rest, "/"); i >= 0 {
		rest = rest[i+1:]
	}
	if n, err := url.PathUnescape(rest); err == nil {
		rest = n
	}
	if v, err := url.PathUnescape(version); err == nil {
		version = v
	}
	return rest, version
}
