// Package discover finds evidence a vendor publishes about its own
// software (see docs/architecture/touchstone.md, "Evidence discovery"):
// security.txt (RFC 9116), CSAF 2.0 provider metadata and the CSAF VEX
// documents it lists, the Transparency Exchange API's /.well-known/tea,
// and GitHub/GitLab repo links on the target page. Every request goes
// through a fetch.Fetcher: the fixed discovery paths as DISCOVERY_PATH,
// and URLs named by a fetched discovery document as DECLARED.
package discover

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/FootprintAI/touchstone/internal/fetch"
	"github.com/FootprintAI/touchstone/internal/pipeline"
	"github.com/FootprintAI/touchstone/internal/sbom"
)

// Per-scan caps on what discovery follows, so one large CSAF provider
// can't spend the whole request budget.
const (
	MaxProviders = 3 // provider-metadata.json documents fetched
	MaxFeeds     = 3 // ROLIE feeds fetched, across providers
	MaxDocuments = 5 // CSAF documents fetched, newest first
)

// Result is what discovery found.
type Result struct {
	// SecurityTxt is the parsed security.txt; nil if none was found.
	SecurityTxt *SecurityTxt
	// ProviderMetadata lists the CSAF provider-metadata.json URLs that
	// were fetched and parsed.
	ProviderMetadata []string
	// VEXDocuments lists the CSAF documents with category csaf_vex that
	// were fetched and parsed.
	VEXDocuments []string
	// TEA is true when /.well-known/tea answered. It is recorded only:
	// querying TEA needs a TEI the site URL does not give (P1).
	TEA bool
	// RepoLinks are the GitHub/GitLab repositories the target page links
	// to, for the repo scan.
	RepoLinks []string
	// Components are the products the CSAF VEX documents name, High
	// confidence with VEX evidence.
	Components []pipeline.Component
}

// Discover probes the target's origin and follows what it declares. The
// target is the URL the reviewer entered (discovery paths are on its
// origin); page is the fetched target page, for repo links. A document
// that was found but can't be read is reported in the error; the rest of
// the result is still returned.
func Discover(ctx context.Context, f fetch.Fetcher, target string, page *fetch.Response) (*Result, error) {
	t, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	origin := t.Scheme + "://" + t.Host
	res := &Result{}
	var errs []error

	if page != nil {
		if base, err := url.Parse(page.URL); err == nil {
			links, err := RepoLinks(base, page.Body)
			if err != nil {
				errs = append(errs, fmt.Errorf("discover: repo links: %w", err))
			}
			res.RepoLinks = links
		}
	}

	// RFC 9116, section 3: /.well-known/ first, the root path as fallback.
	for _, p := range []string{"/.well-known/security.txt", "/security.txt"} {
		if body, ok := get(ctx, f, origin+p, fetch.ReasonDiscoveryPath); ok {
			res.SecurityTxt = ParseSecurityTxt(body)
			break
		}
	}

	// CSAF 2.0, section 7.3: the CSAF fields of security.txt come first,
	// then the well-known provider metadata.
	wellKnown := origin + "/.well-known/csaf/provider-metadata.json"
	var providers []providerDoc
	wkBody, wkFound := get(ctx, f, wellKnown, fetch.ReasonDiscoveryPath)

	// TEA: recorded in the checked list, never parsed or queried.
	_, res.TEA = get(ctx, f, origin+"/.well-known/tea", fetch.ReasonDiscoveryPath)

	if res.SecurityTxt != nil {
		var tried []string
		for _, raw := range res.SecurityTxt.CSAF {
			// Leave room for the well-known one, already fetched.
			if len(tried) >= MaxProviders-1 {
				break
			}
			u, ok := absHTTP(raw)
			if !ok || u == wellKnown || slices.Contains(tried, u) {
				continue
			}
			tried = append(tried, u)
			if body, ok := get(ctx, f, u, fetch.ReasonDeclared); ok {
				providers = append(providers, providerDoc{u, body})
			}
		}
	}
	if wkFound {
		providers = append(providers, providerDoc{wellKnown, wkBody})
	}

	var feeds []string
	for _, p := range providers {
		pm, err := parseProviderMetadata(p.body)
		if err != nil {
			errs = append(errs, fmt.Errorf("discover: %s: %w", p.url, err))
			continue
		}
		res.ProviderMetadata = append(res.ProviderMetadata, p.url)
		for _, feed := range pm.feedURLs() {
			if len(feeds) < MaxFeeds && !slices.Contains(feeds, feed) {
				feeds = append(feeds, feed)
			}
		}
	}

	var entries []feedEntry
	for _, feed := range feeds {
		body, ok := get(ctx, f, feed, fetch.ReasonDeclared)
		if !ok {
			continue
		}
		es, err := parseROLIEFeed(body)
		if err != nil {
			errs = append(errs, fmt.Errorf("discover: %s: %w", feed, err))
			continue
		}
		entries = append(entries, es...)
	}

	for _, doc := range newest(entries, MaxDocuments) {
		body, ok := get(ctx, f, doc, fetch.ReasonDeclared)
		if !ok {
			continue
		}
		d, err := sbom.ParseCSAF(body)
		if err != nil {
			errs = append(errs, fmt.Errorf("discover: %s: %w", doc, err))
			continue
		}
		if !d.VEX {
			continue
		}
		res.VEXDocuments = append(res.VEXDocuments, doc)
		for _, c := range d.Components {
			res.Components = append(res.Components, pipeline.Component{
				Name:       c.Name,
				Version:    c.Version,
				Purl:       c.Purl,
				CPE:        c.CPE,
				Confidence: "HIGH",
				Evidence:   []pipeline.Evidence{{Kind: "VEX", Location: doc, Detail: "CSAF VEX product"}},
			})
		}
	}
	return res, errors.Join(errs...)
}

type providerDoc struct {
	url  string
	body []byte
}

// get fetches u and returns the body of a 2xx answer. Anything else is
// already in the fetcher's checked list.
func get(ctx context.Context, f fetch.Fetcher, u string, reason fetch.Reason) ([]byte, bool) {
	resp, err := f.Get(ctx, u, reason)
	if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, false
	}
	return resp.Body, true
}

func absHTTP(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", false
	}
	return u.String(), true
}

// providerMetadata is the part of a CSAF provider-metadata.json discovery
// reads (CSAF 2.0, section 7.1.20).
type providerMetadata struct {
	CanonicalURL    string `json:"canonical_url"`
	MetadataVersion string `json:"metadata_version"`
	Distributions   []struct {
		ROLIE *struct {
			Feeds []struct {
				URL      string `json:"url"`
				TLPLabel string `json:"tlp_label"`
			} `json:"feeds"`
		} `json:"rolie"`
	} `json:"distributions"`
}

func parseProviderMetadata(body []byte) (*providerMetadata, error) {
	var pm providerMetadata
	if err := json.Unmarshal(body, &pm); err != nil {
		return nil, fmt.Errorf("provider metadata: %v", err)
	}
	if pm.CanonicalURL == "" || pm.MetadataVersion == "" {
		return nil, errors.New("provider metadata: canonical_url and metadata_version are required")
	}
	return &pm, nil
}

// feedURLs returns the provider's public ROLIE feeds. Directory-based
// distributions are not followed: their index files are not named by URL
// in the metadata, and the passive rule forbids synthesizing a path.
func (pm *providerMetadata) feedURLs() []string {
	var out []string
	for _, d := range pm.Distributions {
		if d.ROLIE == nil {
			continue
		}
		for _, feed := range d.ROLIE.Feeds {
			tlp := strings.ToUpper(feed.TLPLabel)
			if tlp != "" && tlp != "WHITE" && tlp != "CLEAR" {
				continue
			}
			if u, ok := absHTTP(feed.URL); ok {
				out = append(out, u)
			}
		}
	}
	return out
}

type rolieFeed struct {
	Feed *struct {
		Entry []struct {
			Updated string `json:"updated"`
			Link    []struct {
				Rel  string `json:"rel"`
				Href string `json:"href"`
			} `json:"link"`
			Content struct {
				Src string `json:"src"`
			} `json:"content"`
		} `json:"entry"`
	} `json:"feed"`
}

type feedEntry struct {
	url     string
	updated time.Time
}

// parseROLIEFeed lists a CSAF ROLIE feed's documents: each entry's
// content src, else its self link.
func parseROLIEFeed(body []byte) ([]feedEntry, error) {
	var rf rolieFeed
	if err := json.Unmarshal(body, &rf); err != nil {
		return nil, fmt.Errorf("ROLIE feed: %v", err)
	}
	if rf.Feed == nil {
		return nil, errors.New("ROLIE feed: no feed object")
	}
	var out []feedEntry
	for _, e := range rf.Feed.Entry {
		href := e.Content.Src
		if href == "" {
			for _, l := range e.Link {
				if l.Rel == "self" {
					href = l.Href
					break
				}
			}
		}
		u, ok := absHTTP(href)
		if !ok {
			continue
		}
		updated, _ := time.Parse(time.RFC3339, e.Updated)
		out = append(out, feedEntry{u, updated})
	}
	return out, nil
}

// newest returns up to n distinct document URLs, most recently updated
// first; entries without a valid timestamp sort last, in feed order.
func newest(entries []feedEntry, n int) []string {
	slices.SortStableFunc(entries, func(a, b feedEntry) int {
		return b.updated.Compare(a.updated)
	})
	var out []string
	for _, e := range entries {
		if len(out) >= n {
			break
		}
		if !slices.Contains(out, e.url) {
			out = append(out, e.url)
		}
	}
	return out
}
