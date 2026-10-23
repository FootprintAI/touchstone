// Package fetch defines the Fetcher seam: the one way any other package
// is allowed to read bytes from a vendor site. The real implementation
// (PassiveFetcher, see docs/architecture/touchstone.md) lands in slice
// S1; this package only fixes the interface so S0 callers and their
// tests can be written against it now.
package fetch

import "context"

// Reason is why a request is allowed. It mirrors the CheckedLocation.reason
// values in proto/touchstone/v1/scan.proto (TARGET, SUBRESOURCE,
// DISCOVERY_PATH, DECLARED); FORGE_API is handled by repo.Forge instead,
// since it never counts against the vendor's request budget.
type Reason string

const (
	ReasonTarget        Reason = "TARGET"
	ReasonSubresource   Reason = "SUBRESOURCE"
	ReasonDiscoveryPath Reason = "DISCOVERY_PATH"
	ReasonDeclared      Reason = "DECLARED"
)

// Response is the subset of an HTTP response any evidence source needs.
type Response struct {
	URL        string
	StatusCode int
	Header     map[string][]string
	Body       []byte
}

// Fetcher is the only interface through which code may contact a vendor
// site. Implementations must refuse any (url, reason) pair outside their
// allowlist.
type Fetcher interface {
	Get(ctx context.Context, url string, reason Reason) (*Response, error)
}
