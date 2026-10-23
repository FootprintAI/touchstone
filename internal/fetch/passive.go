package fetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"

	touchstonev1 "github.com/FootprintAI/touchstone/gen/go/touchstone/v1"
)

// Limits from docs/architecture/touchstone.md, "The passive rule is
// enforced in one place".
const (
	DefaultBudget    = 50
	MaxBudget        = 200
	MaxResponseBytes = 2 << 20  // 2 MiB per response
	MaxScanBytes     = 20 << 20 // 20 MiB per scan
	RequestTimeout   = 10 * time.Second

	maxRedirects = 10
)

// DiscoveryPaths are the only paths a DISCOVERY_PATH request may fetch,
// and only on the target's origin.
var DiscoveryPaths = []string{
	"/.well-known/security.txt",
	"/security.txt",
	"/.well-known/csaf/provider-metadata.json",
	"/.well-known/tea",
}

// ErrRefused is wrapped by every error returned for a request the
// PassiveFetcher would not send (or, for redirects and private
// destinations, would not finish sending).
var ErrRefused = errors.New("fetch: refused")

// Resolver resolves a host name to IP addresses. *net.Resolver satisfies
// it; tests inject a fake so "a name resolving to a private IP" needs no
// real DNS.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Options configures a PassiveFetcher.
type Options struct {
	// Budget is the maximum number of requests (redirect hops included)
	// sent to the vendor. 0 means DefaultBudget; more than MaxBudget is an
	// error.
	Budget uint32
	// AllowPrivate disables the SSRF guard. Only the CLI may set it (for
	// scanning a local fixture); the server must never honor it.
	AllowPrivate bool
	// Version is the tool version reported in the User-Agent.
	Version string
	// Resolver is used for host names; net.DefaultResolver if nil.
	Resolver Resolver
}

// PassiveFetcher is the only Fetcher that talks to a vendor site. It sends
// GET requests only, for one of the allowed reasons, within the request
// budget and size caps, never to a private address, and records every
// request (refused ones included) for the report's checked list.
type PassiveFetcher struct {
	target    *url.URL
	userAgent string
	client    *http.Client

	// Overridable by tests. blocked is the SSRF guard's predicate (nil
	// with AllowPrivate); timeout is RequestTimeout.
	blocked func(netip.Addr) bool
	timeout time.Duration

	mu        sync.Mutex
	budget    uint32
	used      uint32
	scanBytes int64
	checked   []*touchstonev1.CheckedLocation
}

var _ Fetcher = (*PassiveFetcher)(nil)

// New returns a PassiveFetcher for one scan of target, the URL the user
// entered.
func New(target string, opts Options) (*PassiveFetcher, error) {
	t, err := parseHTTPURL(target)
	if err != nil {
		return nil, err
	}
	budget := opts.Budget
	if budget == 0 {
		budget = DefaultBudget
	}
	if budget > MaxBudget {
		return nil, fmt.Errorf("fetch: request budget %d exceeds the maximum of %d", budget, MaxBudget)
	}
	version := opts.Version
	if version == "" {
		version = "dev"
	}
	resolver := opts.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	f := &PassiveFetcher{
		target:    t,
		userAgent: "Touchstone/" + version + " (+https://github.com/FootprintAI/touchstone)",
		timeout:   RequestTimeout,
		budget:    budget,
	}
	if !opts.AllowPrivate {
		f.blocked = IsPrivate
	}
	dialer := &net.Dialer{Timeout: RequestTimeout, Control: f.guardControl}
	f.client = &http.Client{
		Transport: &http.Transport{
			// No proxy: the guard must see the vendor's address, not a proxy's.
			Proxy:                 nil,
			DialContext:           resolvingDialer(dialer, resolver),
			TLSHandshakeTimeout:   RequestTimeout,
			ResponseHeaderTimeout: RequestTimeout,
			MaxIdleConnsPerHost:   2,
		},
		CheckRedirect: f.checkRedirect,
	}
	return f, nil
}

// Get fetches rawURL for reason. Refused requests, transport errors and
// cap violations return an error; any HTTP status is returned as a
// Response. Every call is recorded in Checked.
func (f *PassiveFetcher) Get(ctx context.Context, rawURL string, reason Reason) (*Response, error) {
	u, err := f.allow(rawURL, reason)
	if err != nil {
		f.record(rawURL, reason, touchstonev1.CheckedLocation_RESULT_REFUSED, err)
		return nil, err
	}
	if err := f.reserve(); err != nil {
		f.record(rawURL, reason, touchstonev1.CheckedLocation_RESULT_REFUSED, err)
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()
	resp, err := f.do(ctx, u)
	if err != nil {
		result := touchstonev1.CheckedLocation_RESULT_ERROR
		if errors.Is(err, ErrRefused) {
			result = touchstonev1.CheckedLocation_RESULT_REFUSED
		}
		f.record(rawURL, reason, result, err)
		return nil, err
	}
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		f.record(rawURL, reason, touchstonev1.CheckedLocation_RESULT_FOUND, nil)
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		f.record(rawURL, reason, touchstonev1.CheckedLocation_RESULT_NOT_FOUND, nil)
	default:
		f.record(rawURL, reason, touchstonev1.CheckedLocation_RESULT_ERROR, fmt.Errorf("HTTP %d", resp.StatusCode))
	}
	return resp, nil
}

func (f *PassiveFetcher) do(ctx context.Context, u *url.URL) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", f.userAgent)
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	limit := f.remainingBytes()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	f.addScanBytes(int64(len(body)))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		if limit < MaxResponseBytes {
			return nil, fmt.Errorf("fetch: %s: scan exceeds the %d-byte total cap", u, MaxScanBytes)
		}
		return nil, fmt.Errorf("fetch: %s: response exceeds the %d-byte cap", u, MaxResponseBytes)
	}
	return &Response{
		URL:        resp.Request.URL.String(),
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       body,
	}, nil
}

// allow applies the reason allowlist and returns the parsed URL.
func (f *PassiveFetcher) allow(rawURL string, reason Reason) (*url.URL, error) {
	u, err := parseHTTPURL(rawURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRefused, err)
	}
	switch reason {
	case ReasonTarget:
		if u.String() != f.target.String() {
			return nil, fmt.Errorf("%w: TARGET must be the scanned URL %s, got %s", ErrRefused, f.target, u)
		}
	case ReasonDiscoveryPath:
		if !sameOrigin(u, f.target) || u.RawQuery != "" || !slices.Contains(DiscoveryPaths, u.EscapedPath()) {
			return nil, fmt.Errorf("%w: %s is not a discovery path on %s", ErrRefused, u, origin(f.target))
		}
	case ReasonSubresource, ReasonDeclared:
		// Taken from a fetched document by the caller; nothing to check
		// beyond the URL itself.
	default:
		return nil, fmt.Errorf("%w: reason %q is not allowed", ErrRefused, reason)
	}
	return u, nil
}

// reserve spends one request from the budget.
func (f *PassiveFetcher) reserve() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.used >= f.budget {
		return fmt.Errorf("%w: request budget of %d exhausted", ErrRefused, f.budget)
	}
	if f.scanBytes >= MaxScanBytes {
		return fmt.Errorf("%w: scan reached the %d-byte total cap", ErrRefused, MaxScanBytes)
	}
	f.used++
	return nil
}

func (f *PassiveFetcher) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("%w: more than %d redirects", ErrRefused, maxRedirects)
	}
	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		return fmt.Errorf("%w: redirect to non-http(s) URL %s", ErrRefused, req.URL)
	}
	// The redirect target's address is checked by the dial guard.
	return f.reserve()
}

func (f *PassiveFetcher) remainingBytes() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return min(MaxResponseBytes, MaxScanBytes-f.scanBytes)
}

func (f *PassiveFetcher) addScanBytes(n int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scanBytes += n
}

func (f *PassiveFetcher) record(rawURL string, reason Reason, result touchstonev1.CheckedLocation_Result, err error) {
	loc := &touchstonev1.CheckedLocation{Url: rawURL, Reason: string(reason), Result: result}
	if err != nil {
		loc.Error = err.Error()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checked = append(f.checked, loc)
}

// Checked returns the request log in call order, for ScanReport.checked.
func (f *PassiveFetcher) Checked() []*touchstonev1.CheckedLocation {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.checked)
}

// RequestsUsed returns how many requests were sent, redirect hops
// included, for ScanReport.requests_used.
func (f *PassiveFetcher) RequestsUsed() uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.used
}

// RequestBudget returns the effective budget, for ScanReport.request_budget.
func (f *PassiveFetcher) RequestBudget() uint32 {
	return f.budget
}

func parseHTTPURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("fetch: invalid URL %q: %v", raw, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("fetch: %q is not an absolute http(s) URL", raw)
	}
	if u.User != nil {
		return nil, fmt.Errorf("fetch: %q carries credentials", raw)
	}
	return u, nil
}

func origin(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	return u.Scheme + "://" + net.JoinHostPort(u.Hostname(), port)
}

func sameOrigin(a, b *url.URL) bool {
	return origin(a) == origin(b)
}

// resolvingDialer resolves host names with r and dials each address with
// d, so d.Control sees every IP actually connected to.
func resolvingDialer(d *net.Dialer, r Resolver) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if _, err := netip.ParseAddr(host); err == nil {
			return d.DialContext(ctx, network, addr)
		}
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return nil, err
		}
		ips, err := r.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("fetch: no addresses for %s", host)
		}
		var errs []error
		for _, ip := range ips {
			conn, err := d.DialContext(ctx, network, netip.AddrPortFrom(ip.Unmap(), uint16(port)).String())
			if err == nil {
				return conn, nil
			}
			errs = append(errs, err)
		}
		return nil, errors.Join(errs...)
	}
}

// guardControl is the net.Dialer.Control hook of the SSRF guard: it runs
// after resolution, right before connect, so it covers host names,
// DNS rebinding and redirects alike.
func (f *PassiveFetcher) guardControl(_, address string, _ syscall.RawConn) error {
	if f.blocked == nil {
		return nil
	}
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: unparseable dial address %q", ErrRefused, address)
	}
	if ip := ap.Addr(); f.blocked(ip) {
		return fmt.Errorf("%w: %s is a private or reserved address", ErrRefused, ip)
	}
	return nil
}

var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),     // "this network"
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT, RFC 6598
}

// IsPrivate reports whether the SSRF guard refuses ip: loopback, RFC 1918,
// link-local (incl. 169.254.169.254), CGNAT, IPv6 ULA (fc00::/7),
// unspecified and multicast addresses.
func IsPrivate(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
