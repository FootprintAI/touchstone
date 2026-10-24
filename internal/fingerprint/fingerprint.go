// Package fingerprint detects libraries from the URLs of fetched scripts,
// from response headers, and from the <script src> references in a page
// (see docs/architecture/touchstone.md, "Fingerprinting"). It does no I/O:
// callers fetch the bytes and pass them in.
package fingerprint

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/FootprintAI/touchstone/internal/pipeline"
	"github.com/dlclark/regexp2"
	"golang.org/x/net/html"
)

// matchTimeout bounds every regexp2 match. Retire.js patterns backtrack,
// and the URLs they run against come from attacker-controlled pages.
const matchTimeout = 100 * time.Millisecond

//go:embed data/signatures.json
var signatureData []byte

// signatureFile is the on-disk shape of data/signatures.json.
type signatureFile struct {
	Libraries []struct {
		Name       string `json:"name"`
		Purl       string `json:"purl"`
		CPE        string `json:"cpe"`
		Extractors struct {
			URI      []string `json:"uri"`
			Filename []string `json:"filename"`
		} `json:"extractors"`
	} `json:"libraries"`
}

// library is one compiled signature entry.
type library struct {
	name, purl, cpe string
	uri, filename   []*regexp2.Regexp
}

// libraries is compiled once at start-up from the embedded signatures. A
// bad pattern is a build-time bug, so it panics; TestSignaturesCompile
// keeps it from shipping.
var libraries = mustCompile(signatureData)

func mustCompile(data []byte) []library {
	libs, err := compile(data)
	if err != nil {
		panic(err)
	}
	return libs
}

func compile(data []byte) ([]library, error) {
	var sf signatureFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return nil, fmt.Errorf("fingerprint: signatures: %w", err)
	}
	var out []library
	for _, l := range sf.Libraries {
		lib := library{name: l.Name, purl: l.Purl, cpe: l.CPE}
		var err error
		if lib.uri, err = compileAll(l.Name, "uri", l.Extractors.URI); err != nil {
			return nil, err
		}
		if lib.filename, err = compileAll(l.Name, "filename", l.Extractors.Filename); err != nil {
			return nil, err
		}
		out = append(out, lib)
	}
	return out, nil
}

func compileAll(name, extractor string, patterns []string) ([]*regexp2.Regexp, error) {
	var out []*regexp2.Regexp
	for _, p := range patterns {
		re, err := regexp2.Compile(p, regexp2.ECMAScript)
		if err != nil {
			return nil, fmt.Errorf("fingerprint: %s %s pattern %q: %w", name, extractor, p, err)
		}
		re.MatchTimeout = matchTimeout
		out = append(out, re)
	}
	return out, nil
}

// FromURL matches a script URL against the uri extractors (the whole URL)
// and the filename extractors (its last path segment). Each library it
// recognises yields one Low-confidence component, with the URL as
// evidence. A match that times out is reported as an error and skipped.
func FromURL(assetURL string) ([]pipeline.Component, error) {
	u, err := url.Parse(assetURL)
	if err != nil {
		return nil, fmt.Errorf("fingerprint: %q: %w", assetURL, err)
	}
	base := path.Base(u.Path)
	var out []pipeline.Component
	var errs []error
	for _, lib := range libraries {
		for _, probe := range []struct {
			input string
			res   []*regexp2.Regexp
		}{{assetURL, lib.uri}, {base, lib.filename}} {
			c, ok, err := lib.match(probe.input, probe.res)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if !ok {
				continue
			}
			c.Evidence = []pipeline.Evidence{{
				Kind:     "FINGERPRINT_ASSET",
				Location: assetURL,
				Detail:   c.Evidence[0].Detail,
			}}
			out = append(out, c)
			break
		}
	}
	return out, errors.Join(errs...)
}

// match runs res against input and, on the first hit, builds a component
// with the captured version. The evidence detail is the matched text.
func (l library) match(input string, res []*regexp2.Regexp) (pipeline.Component, bool, error) {
	for _, re := range res {
		m, err := re.FindStringMatch(input)
		if err != nil {
			return pipeline.Component{}, false, fmt.Errorf("fingerprint: %s: %w", l.name, err)
		}
		if m == nil {
			continue
		}
		version := m.GroupByNumber(1).String()
		c := pipeline.Component{
			Name:       l.name,
			Version:    version,
			Purl:       strings.ReplaceAll(l.purl, "{version}", version),
			CPE:        strings.ReplaceAll(l.cpe, "{version}", version),
			Confidence: "LOW",
			Evidence:   []pipeline.Evidence{{Detail: m.String()}},
		}
		return c, true, nil
	}
	return pipeline.Component{}, false, nil
}

// headerRule maps one response header value to a component. Banners
// describe the server software, which distributions may patch without
// changing the version string, hence the MAY_BE_BACKPORTED caveat.
type headerRule struct {
	header string
	re     *regexp.Regexp
	name   string
	cpe    string // %s is the captured version
}

var headerRules = []headerRule{
	{"Server", regexp.MustCompile(`^Apache/([0-9]+(?:\.[0-9]+)+)`), "apache http_server", "cpe:2.3:a:apache:http_server:%s:*:*:*:*:*:*:*"},
	{"Server", regexp.MustCompile(`^nginx/([0-9]+(?:\.[0-9]+)+)`), "nginx", "cpe:2.3:a:f5:nginx:%s:*:*:*:*:*:*:*"},
	{"X-Powered-By", regexp.MustCompile(`^PHP/([0-9]+(?:\.[0-9]+)+)`), "php", "cpe:2.3:a:php:php:%s:*:*:*:*:*:*:*"},
}

// FromHeaders reads the Server and X-Powered-By banners of a response
// from pageURL. Each recognised banner yields one Low-confidence component
// with a CPE and no purl, so it is not looked up by purl.
func FromHeaders(pageURL string, h http.Header) []pipeline.Component {
	var out []pipeline.Component
	for _, rule := range headerRules {
		for _, value := range h.Values(rule.header) {
			m := rule.re.FindStringSubmatch(value)
			if m == nil {
				continue
			}
			out = append(out, pipeline.Component{
				Name:       rule.name,
				Version:    m[1],
				CPE:        fmt.Sprintf(rule.cpe, m[1]),
				Confidence: "LOW",
				Evidence: []pipeline.Evidence{{
					Kind:     "FINGERPRINT_HEADER",
					Location: pageURL,
					Detail:   rule.header + ": " + value,
				}},
				Caveats: []string{"MAY_BE_BACKPORTED"},
			})
		}
	}
	return out
}

// ScriptURLs returns the absolute http(s) URLs of the <script src>
// elements in an HTML page, resolved against the page URL, in document
// order and without duplicates.
func ScriptURLs(page *url.URL, body []byte) ([]string, error) {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("fingerprint: parse page: %w", err)
	}
	seen := map[string]bool{}
	var out []string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "script" {
			for _, a := range n.Attr {
				if a.Key != "src" {
					continue
				}
				ref, err := url.Parse(strings.TrimSpace(a.Val))
				if err != nil {
					break
				}
				abs := page.ResolveReference(ref)
				if (abs.Scheme == "http" || abs.Scheme == "https") && !seen[abs.String()] {
					seen[abs.String()] = true
					out = append(out, abs.String())
				}
				break
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return out, nil
}
