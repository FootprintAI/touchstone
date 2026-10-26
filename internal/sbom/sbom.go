// Package sbom extracts components from SBOM and VEX documents
// (CycloneDX, SPDX, OpenVEX and CSAF 2.0 VEX). It does no I/O: callers
// fetch the bytes and pass them in. Only the components are read here;
// applying VEX statements to vulnerabilities lands with slice S4.
package sbom

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Format is the kind of document Parse recognised.
type Format string

const (
	CycloneDX Format = "CYCLONEDX"
	SPDX      Format = "SPDX"
	OpenVEX   Format = "OPENVEX"
	CSAFVEX   Format = "CSAF_VEX"
)

// ErrUnknownFormat is returned for well-formed JSON that is none of the
// supported formats (including CSAF documents that are not VEX).
var ErrUnknownFormat = errors.New("sbom: not a supported SBOM or VEX document")

// Component is one product named by a document.
type Component struct {
	Name    string
	Version string
	Purl    string
	CPE     string
}

// Document is the normalized content of one SBOM or VEX document.
type Document struct {
	Format     Format
	Components []Component
}

type cdxComponent struct {
	Name       string         `json:"name"`
	Version    string         `json:"version"`
	Purl       string         `json:"purl"`
	CPE        string         `json:"cpe"`
	Components []cdxComponent `json:"components"`
}

type spdxPackage struct {
	Name        string `json:"name"`
	VersionInfo string `json:"versionInfo"`
	ExternalRef []struct {
		Type    string `json:"referenceType"`
		Locator string `json:"referenceLocator"`
	} `json:"externalRefs"`
}

type csafProduct struct {
	Name   string `json:"name"`
	Helper struct {
		Purl string `json:"purl"`
		CPE  string `json:"cpe"`
	} `json:"product_identification_helper"`
}

type csafBranch struct {
	Product  *csafProduct `json:"product"`
	Branches []csafBranch `json:"branches"`
}

type raw struct {
	BomFormat  string         `json:"bomFormat"`
	Components []cdxComponent `json:"components"`

	SPDXVersion string        `json:"spdxVersion"`
	Packages    []spdxPackage `json:"packages"`

	Context    string `json:"@context"`
	Statements []struct {
		Products []struct {
			ID          string            `json:"@id"`
			Identifiers map[string]string `json:"identifiers"`
		} `json:"products"`
	} `json:"statements"`

	Document struct {
		Category string `json:"category"`
	} `json:"document"`
	ProductTree struct {
		Branches         []csafBranch  `json:"branches"`
		FullProductNames []csafProduct `json:"full_product_names"`
	} `json:"product_tree"`
}

// Parse decodes one document. Malformed JSON is an error wrapping the
// decoder's; JSON that is not a supported format is ErrUnknownFormat.
func Parse(b []byte) (*Document, error) {
	var r raw
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("sbom: %w", err)
	}
	var doc Document
	switch {
	case r.BomFormat == "CycloneDX":
		doc.Format = CycloneDX
		cdx(&doc, r.Components)
	case strings.HasPrefix(r.SPDXVersion, "SPDX-"):
		doc.Format = SPDX
		for _, p := range r.Packages {
			c := Component{Name: p.Name, Version: p.VersionInfo}
			for _, ref := range p.ExternalRef {
				switch ref.Type {
				case "purl":
					c.Purl = ref.Locator
				case "cpe23Type":
					c.CPE = ref.Locator
				}
			}
			doc.add(c)
		}
	case strings.Contains(r.Context, "openvex"):
		doc.Format = OpenVEX
		for _, s := range r.Statements {
			for _, p := range s.Products {
				id := p.ID
				if v := p.Identifiers["purl"]; v != "" {
					id = v
				}
				if strings.HasPrefix(id, "pkg:") {
					doc.add(Component{Purl: id})
				}
			}
		}
	case r.Document.Category == "csaf_vex":
		doc.Format = CSAFVEX
		for _, p := range r.ProductTree.FullProductNames {
			doc.addCSAF(p)
		}
		var walk func([]csafBranch)
		walk = func(bs []csafBranch) {
			for _, b := range bs {
				if b.Product != nil {
					doc.addCSAF(*b.Product)
				}
				walk(b.Branches)
			}
		}
		walk(r.ProductTree.Branches)
	default:
		return nil, ErrUnknownFormat
	}
	return &doc, nil
}

func cdx(doc *Document, cs []cdxComponent) {
	for _, c := range cs {
		doc.add(Component{Name: c.Name, Version: c.Version, Purl: c.Purl, CPE: c.CPE})
		cdx(doc, c.Components)
	}
}

func (d *Document) addCSAF(p csafProduct) {
	c := Component{Name: p.Name, Purl: p.Helper.Purl, CPE: p.Helper.CPE}
	// A CSAF product name is display text ("Foo 1.2 on Linux"); the purl's
	// name and version are the machine-readable ones.
	if name, version := splitPurl(c.Purl); name != "" {
		c.Name, c.Version = name, version
	}
	d.add(c)
}

// add fills a missing name or version from the purl, and skips
// components that name nothing or repeat an earlier one.
func (d *Document) add(c Component) {
	if name, version := splitPurl(c.Purl); c.Purl != "" {
		if c.Name == "" {
			c.Name = name
		}
		if c.Version == "" {
			c.Version = version
		}
	}
	if c.Name == "" {
		return
	}
	for _, e := range d.Components {
		if e.Name == c.Name && e.Version == c.Version && e.Purl == c.Purl {
			return
		}
	}
	d.Components = append(d.Components, c)
}

// splitPurl returns the name and version of a package URL
// (pkg:type/namespace/name@version?qualifiers#subpath).
func splitPurl(purl string) (name, version string) {
	s := strings.TrimPrefix(purl, "pkg:")
	s, _, _ = strings.Cut(s, "#")
	s, _, _ = strings.Cut(s, "?")
	if i := strings.LastIndex(s, "@"); i >= 0 {
		version, _ = url.PathUnescape(s[i+1:])
		s = s[:i]
	}
	if i := strings.LastIndex(s, "/"); i >= 0 {
		s = s[i+1:]
	}
	name, _ = url.PathUnescape(s)
	return name, version
}
