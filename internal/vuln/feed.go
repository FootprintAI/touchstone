package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// maxFeedBytes caps one NVD, KEV or EPSS response. The KEV catalog, the
// largest of them, is a few megabytes.
const maxFeedBytes = 16 << 20

// defaultFeedTimeout bounds one request to a vulnerability feed.
const defaultFeedTimeout = 10 * time.Second

// getJSON GETs rawURL with the given extra headers and decodes the reply into
// out. Any non-200 status is an error, so a failed feed is never read as
// "nothing listed".
func getJSON(ctx context.Context, client *http.Client, rawURL string, header http.Header, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes+1))
	if err != nil {
		return err
	}
	if len(b) > maxFeedBytes {
		return fmt.Errorf("response exceeds %d bytes", maxFeedBytes)
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	return nil
}

// cveIDs returns the distinct CVE ids among ids, in first-seen order. KEV and
// EPSS only score CVE ids, so other ids (GHSA, PYSEC, ...) are dropped before
// any request is made.
func cveIDs(ids []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, id := range ids {
		if strings.HasPrefix(id, "CVE-") && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}
