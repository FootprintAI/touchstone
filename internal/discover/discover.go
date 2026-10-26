// Package discover finds the evidence a vendor publishes about itself:
// security.txt (RFC 9116), CSAF provider metadata and the VEX documents it
// points to, the /.well-known/tea record, and source-repo links in the
// page (see docs/architecture/touchstone.md, "Evidence discovery"). Every
// request goes through a fetch.Fetcher, so the passive rule and the
// checked list are enforced there, not here.
package discover

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/FootprintAI/touchstone/internal/fetch"
	"github.com/FootprintAI/touchstone/internal/sbom"
)

// MaxVEXDocuments bounds how many documents named by CSAF ROLIE feeds are
// fetched in one scan; the request budget bounds the rest.
const MaxVEXDocuments = 10

const (
	pathSecurityTxt     = "/.well-known/security.txt"
	pathSecurityTxtOld  = "/security.txt"
	pathProviderMeta    = "/.well-known/csaf/provider-metadata.json"
	pathTEA             = "/.well-known/tea"
	maxROLIEFeedsPerRun = 3
)

// VEX is one parsed CSAF VEX document and the URL it came from.
type VEX struct {
	URL string
	Doc *sbom.Document
}

// Result is what discovery found. Errors lists documents that were
// fetched but could not be understood; fetch failures are in the
// fetcher's checked list instead.
type Result struct {
	VEX       []VEX
	RepoLinks []string
	Errors    []error
}

// SecurityTxt is the part of an RFC 9116 file that discovery uses.
type SecurityTxt struct {
	CSAF    []string
	Contact []string
}

// ParseSecurityTxt reads an RFC 9116 security.txt. Field names are case
// insensitive, lines may end in CRLF, comments and unknown fields are
// ignored, and CSAF: may appear any number of times.
func ParseSecurityTxt(b []byte) SecurityTxt {
	var out SecurityTxt
	text := strings.TrimPrefix(string(b), "\ufeff")
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		value = strings.TrimSpace(value)
		if !ok || value == "" {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "csaf":
			out.CSAF = append(out.CSAF, value)
		case "contact":
			out.Contact = append(out.Contact, value)
		}
	}
	return out
}

// Run probes the discovery paths on target's origin, follows what they
// declare, and extracts repo links from page. Nothing here fails the
// scan: an unreachable or malformed document is recorded and skipped.
func Run(ctx context.Context, f fetch.Fetcher, target *url.URL, page []byte) *Result {
	r := &Result{}
	d := &run{ctx: ctx, f: f, target: target, res: r, seen: map[string]bool{}}

	if body, u := d.probe(pathSecurityTxt); body != nil {
		d.securityTxt(body, u)
	} else if body, u := d.probe(pathSecurityTxtOld); body != nil {
		d.securityTxt(body, u)
	}
	if body, u := d.probe(pathProviderMeta); body != nil {
		d.providerMetadata(body, u)
	}
	// The TEA record is only recorded: querying it needs a TEI the site
	// URL doesn't give us.
	d.probe(pathTEA)

	r.RepoLinks = RepoLinks(target, page)
	return r
}

type run struct {
	ctx    context.Context
	f      fetch.Fetcher
	target *url.URL
	res    *Result
	seen   map[string]bool
	docs   int
}

// probe fetches one fixed discovery path on the target's origin and
// returns the body of a 2xx response.
func (d *run) probe(path string) ([]byte, *url.URL) {
	u := d.target.ResolveReference(&url.URL{Path: path})
	return d.get(u.String(), fetch.ReasonDiscoveryPath)
}

// get fetches rawURL once per scan; a 2xx body is returned with its URL.
func (d *run) get(rawURL string, reason fetch.Reason) ([]byte, *url.URL) {
	if d.seen[rawURL] {
		return nil, nil
	}
	d.seen[rawURL] = true
	resp, err := d.f.Get(d.ctx, rawURL, reason)
	if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil
	}
	u, err := url.Parse(resp.URL)
	if err != nil || resp.URL == "" {
		u, _ = url.Parse(rawURL)
	}
	return resp.Body, u
}

func (d *run) securityTxt(body []byte, base *url.URL) {
	for _, ref := range ParseSecurityTxt(body).CSAF {
		u, ok := resolveHTTP(base, ref)
		if !ok {
			d.res.Errors = append(d.res.Errors, fmt.Errorf("security.txt: CSAF %q is not an http(s) URL", ref))
			continue
		}
		if meta, mu := d.get(u, fetch.ReasonDeclared); meta != nil {
			d.providerMetadata(meta, mu)
		}
	}
}

type providerMetadata struct {
	Distributions []struct {
		Rolie struct {
			Feeds []struct {
				URL string `json:"url"`
			} `json:"feeds"`
		} `json:"rolie"`
	} `json:"distributions"`
}

type rolieFeed struct {
	Feed struct {
		Entry []struct {
			Content struct {
				Src string `json:"src"`
			} `json:"content"`
		} `json:"entry"`
	} `json:"feed"`
}

// providerMetadata follows the ROLIE feeds a provider-metadata.json
// declares to the documents they list. Only URLs the metadata names are
// fetched; the directory layout is never guessed.
func (d *run) providerMetadata(body []byte, base *url.URL) {
	var pm providerMetadata
	if err := json.Unmarshal(body, &pm); err != nil {
		d.res.Errors = append(d.res.Errors, fmt.Errorf("CSAF provider metadata %s: %w", base, err))
		return
	}
	feeds := 0
	for _, dist := range pm.Distributions {
		for _, fd := range dist.Rolie.Feeds {
			feedURL, ok := resolveHTTP(base, fd.URL)
			if !ok || feeds >= maxROLIEFeedsPerRun {
				continue
			}
			feeds++
			feedBody, fu := d.get(feedURL, fetch.ReasonDeclared)
			if feedBody == nil {
				continue
			}
			var feed rolieFeed
			if err := json.Unmarshal(feedBody, &feed); err != nil {
				d.res.Errors = append(d.res.Errors, fmt.Errorf("ROLIE feed %s: %w", fu, err))
				continue
			}
			for _, e := range feed.Feed.Entry {
				if docURL, ok := resolveHTTP(fu, e.Content.Src); ok {
					d.vex(docURL)
				}
			}
		}
	}
}

// vex fetches one declared CSAF document and keeps it if it is a VEX.
// Other CSAF documents (plain advisories) are ignored.
func (d *run) vex(docURL string) {
	if d.docs >= MaxVEXDocuments {
		return
	}
	body, u := d.get(docURL, fetch.ReasonDeclared)
	if body == nil {
		return
	}
	d.docs++
	doc, err := sbom.Parse(body)
	switch {
	case errors.Is(err, sbom.ErrUnknownFormat):
	case err != nil:
		d.res.Errors = append(d.res.Errors, fmt.Errorf("%s: %w", u, err))
	default:
		d.res.VEX = append(d.res.VEX, VEX{URL: u.String(), Doc: doc})
	}
}

func resolveHTTP(base *url.URL, ref string) (string, bool) {
	r, err := url.Parse(strings.TrimSpace(ref))
	if err != nil || ref == "" {
		return "", false
	}
	abs := base.ResolveReference(r)
	if (abs.Scheme != "http" && abs.Scheme != "https") || abs.Host == "" {
		return "", false
	}
	return abs.String(), true
}
