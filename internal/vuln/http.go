package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// getJSON sends one GET to a vulnerability feed and decodes the reply into
// out. Like OSV.do, any non-200 status is an error, so a failed lookup is
// never read as "no vulnerabilities". name prefixes every error.
func getJSON(ctx context.Context, client *http.Client, name, rawURL string, header http.Header, maxBytes int64, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%s: GET: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: GET: HTTP %d", name, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return fmt.Errorf("%s: GET: %w", name, err)
	}
	if int64(len(b)) > maxBytes {
		return fmt.Errorf("%s: GET: response exceeds %d bytes", name, maxBytes)
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("%s: GET: decode: %w", name, err)
	}
	return nil
}
