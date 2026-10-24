package vuln

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultOSVURL is the public OSV.dev API.
const DefaultOSVURL = "https://api.osv.dev"

// maxOSVResponseBytes caps one OSV response; the API's replies are small.
const maxOSVResponseBytes = 2 << 20

// OSV is the vuln.Source that asks OSV.dev for vulnerabilities by purl.
// It calls the API with its own client, so its requests don't count
// against the vendor's request budget (see docs/architecture/touchstone.md).
type OSV struct {
	BaseURL string
	Client  *http.Client
}

// NewOSV returns an OSV source for the public API with a 10 s timeout per
// request.
func NewOSV() *OSV {
	return &OSV{BaseURL: DefaultOSVURL, Client: &http.Client{Timeout: 10 * time.Second}}
}

var _ Source = (*OSV)(nil)

func (o *OSV) Name() string { return "OSV" }

// osvBatchRequest and osvBatchResponse are the wire shapes of
// POST /v1/querybatch. Only the fields Touchstone reads are declared.
type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvQuery struct {
	Package osvPackage `json:"package"`
}

type osvPackage struct {
	Purl string `json:"purl"`
}

type osvBatchResponse struct {
	Results []struct {
		Vulns []osvVuln `json:"vulns"`
	} `json:"results"`
}

// osvVuln is one advisory as returned by /v1/querybatch (id only) and by
// GET /v1/vulns/{id} (everything else).
type osvVuln struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases"`
	Summary string   `json:"summary"`
}

// Lookup returns the advisories for every query that carries a purl. CPE
// queries are ignored (NVD handles those, slice S3). Advisories are fetched
// with one querybatch call, then one GET per distinct id for details.
func (o *OSV) Lookup(ctx context.Context, queries []Query) ([]Finding, error) {
	var req osvBatchRequest
	for _, q := range queries {
		if q.Purl != "" {
			req.Queries = append(req.Queries, osvQuery{Package: osvPackage{Purl: q.Purl}})
		}
	}
	if len(req.Queries) == 0 {
		return nil, nil
	}

	var batch osvBatchResponse
	if err := o.do(ctx, http.MethodPost, "/v1/querybatch", req, &batch); err != nil {
		return nil, err
	}
	if len(batch.Results) != len(req.Queries) {
		return nil, fmt.Errorf("osv: querybatch returned %d results for %d queries", len(batch.Results), len(req.Queries))
	}

	seen := map[string]bool{}
	var ids []string
	for _, r := range batch.Results {
		for _, v := range r.Vulns {
			if v.ID != "" && !seen[v.ID] {
				seen[v.ID] = true
				ids = append(ids, v.ID)
			}
		}
	}

	var out []Finding
	for _, id := range ids {
		var v osvVuln
		if err := o.do(ctx, http.MethodGet, "/v1/vulns/"+url.PathEscape(id), nil, &v); err != nil {
			return nil, err
		}
		out = append(out, findingFromOSV(id, v))
	}
	return out, nil
}

// findingFromOSV uses the CVE alias as the finding id when there is one,
// as the report's Vulnerability.id contract requires, else the OSV id.
func findingFromOSV(id string, v osvVuln) Finding {
	f := Finding{ID: id, Aliases: v.Aliases, Summary: v.Summary}
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			f.ID = a
			break
		}
	}
	if f.ID != id {
		f.Aliases = append([]string{id}, v.Aliases...)
	}
	return f
}

// do sends one JSON request to the OSV API and decodes the reply into out.
// Any non-200 status is an error, so a failed lookup is never read as "no
// vulnerabilities".
func (o *OSV) do(ctx context.Context, method, path string, body any, out any) error {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, o.BaseURL+path, r)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := o.Client.Do(req)
	if err != nil {
		return fmt.Errorf("osv: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("osv: %s %s: HTTP %d", method, path, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxOSVResponseBytes+1))
	if err != nil {
		return fmt.Errorf("osv: %s %s: %w", method, path, err)
	}
	if len(b) > maxOSVResponseBytes {
		return fmt.Errorf("osv: %s %s: response exceeds %d bytes", method, path, maxOSVResponseBytes)
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("osv: %s %s: decode: %w", method, path, err)
	}
	return nil
}
