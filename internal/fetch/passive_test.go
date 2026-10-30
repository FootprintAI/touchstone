package fetch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	touchstonev1 "github.com/FootprintAI/touchstone/gen/go/touchstone/v1"
)

// seen records what an httptest server received.
type seen struct {
	mu   sync.Mutex
	reqs []*http.Request
}

func (s *seen) add(r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reqs = append(s.reqs, r)
}

func (s *seen) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.reqs)
}

// okServer answers every request with 200 "ok" and records it.
func okServer(t *testing.T) (*httptest.Server, *seen) {
	t.Helper()
	s := &seen{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.add(r)
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(srv.Close)
	return srv, s
}

func mustNew(t *testing.T, target string, opts Options) *PassiveFetcher {
	t.Helper()
	f, err := New(target, opts)
	if err != nil {
		t.Fatalf("New(%q): %v", target, err)
	}
	return f
}

func lastChecked(t *testing.T, f *PassiveFetcher) *touchstonev1.CheckedLocation {
	t.Helper()
	c := f.Checked()
	if len(c) == 0 {
		t.Fatal("Checked: empty, want the request recorded")
	}
	return c[len(c)-1]
}

func TestAllowReason(t *testing.T) {
	srv, s := okServer(t)
	target := srv.URL + "/"
	tests := []struct {
		name    string
		url     string
		reason  Reason
		refused bool
	}{
		{"target", target, ReasonTarget, false},
		{"target other path", srv.URL + "/admin", ReasonTarget, true},
		{"subresource", srv.URL + "/static/app.js", ReasonSubresource, false},
		{"declared", srv.URL + "/csaf/advisory.json", ReasonDeclared, false},
		{"discovery security.txt", srv.URL + "/.well-known/security.txt", ReasonDiscoveryPath, false},
		{"discovery root security.txt", srv.URL + "/security.txt", ReasonDiscoveryPath, false},
		{"discovery csaf", srv.URL + "/.well-known/csaf/provider-metadata.json", ReasonDiscoveryPath, false},
		{"discovery tea", srv.URL + "/.well-known/tea", ReasonDiscoveryPath, false},
		{"discovery unknown path", srv.URL + "/.env", ReasonDiscoveryPath, true},
		{"discovery with query", srv.URL + "/.well-known/security.txt?x=1", ReasonDiscoveryPath, true},
		{"discovery other origin", "https://other.example/.well-known/security.txt", ReasonDiscoveryPath, true},
		{"supplied", srv.URL + "/sbom.json", ReasonSupplied, false},
		{"supplied other URL", srv.URL + "/other.json", ReasonSupplied, true},
		{"forge api reason", srv.URL + "/repos/x", Reason("FORGE_API"), true},
		{"empty reason", srv.URL + "/x", Reason(""), true},
		{"unknown reason", srv.URL + "/x", Reason("CRAWL"), true},
		{"non-http scheme", "ftp://example.com/x", ReasonSubresource, true},
		{"credentials in URL", "http://user:pw@" + strings.TrimPrefix(srv.URL, "http://") + "/x", ReasonSubresource, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := mustNew(t, target, Options{AllowPrivate: true, SuppliedURL: srv.URL + "/sbom.json"})
			before := s.count()
			_, err := f.Get(context.Background(), tt.url, tt.reason)
			got := lastChecked(t, f)
			if got.GetUrl() != tt.url || got.GetReason() != string(tt.reason) {
				t.Errorf("Checked = %v, want url %q reason %q", got, tt.url, tt.reason)
			}
			if tt.refused {
				if !errors.Is(err, ErrRefused) {
					t.Fatalf("Get: err = %v, want ErrRefused", err)
				}
				if got.GetResult() != touchstonev1.CheckedLocation_RESULT_REFUSED {
					t.Errorf("result = %v, want RESULT_REFUSED", got.GetResult())
				}
				if s.count() != before {
					t.Error("refused request reached the server")
				}
				if f.RequestsUsed() != 0 {
					t.Errorf("RequestsUsed = %d, want 0 for a refused request", f.RequestsUsed())
				}
				return
			}
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if got.GetResult() != touchstonev1.CheckedLocation_RESULT_FOUND {
				t.Errorf("result = %v, want RESULT_FOUND", got.GetResult())
			}
		})
	}
}

func TestSuppliedRefusedWithoutSuppliedURL(t *testing.T) {
	srv, s := okServer(t)
	f := mustNew(t, srv.URL+"/", Options{AllowPrivate: true})
	if _, err := f.Get(context.Background(), srv.URL+"/sbom.json", ReasonSupplied); !errors.Is(err, ErrRefused) {
		t.Fatalf("Get: err = %v, want ErrRefused", err)
	}
	if s.count() != 0 {
		t.Error("refused request reached the server")
	}
}

func TestRequestIsPassiveGET(t *testing.T) {
	srv, s := okServer(t)
	f := mustNew(t, srv.URL+"/page", Options{AllowPrivate: true, Version: "1.2.3"})
	if _, err := f.Get(context.Background(), srv.URL+"/page", ReasonTarget); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := f.Get(context.Background(), srv.URL+"/app.js", ReasonSubresource); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if s.count() != 2 {
		t.Fatalf("server saw %d requests, want 2", s.count())
	}
	for _, r := range s.reqs {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if ua := r.Header.Get("User-Agent"); ua != "Touchstone/1.2.3 (+https://github.com/FootprintAI/touchstone)" {
			t.Errorf("User-Agent = %q", ua)
		}
		if r.URL.RawQuery != "" {
			t.Errorf("query %q added to %s", r.URL.RawQuery, r.URL.Path)
		}
	}
}

func TestResultFromStatus(t *testing.T) {
	tests := []struct {
		status int
		want   touchstonev1.CheckedLocation_Result
	}{
		{200, touchstonev1.CheckedLocation_RESULT_FOUND},
		{404, touchstonev1.CheckedLocation_RESULT_NOT_FOUND},
		{410, touchstonev1.CheckedLocation_RESULT_NOT_FOUND},
		{500, touchstonev1.CheckedLocation_RESULT_ERROR},
	}
	for _, tt := range tests {
		t.Run(strconv.Itoa(tt.status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
			}))
			defer srv.Close()
			f := mustNew(t, srv.URL, Options{AllowPrivate: true})
			resp, err := f.Get(context.Background(), srv.URL, ReasonTarget)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if resp.StatusCode != tt.status {
				t.Errorf("StatusCode = %d, want %d", resp.StatusCode, tt.status)
			}
			if got := lastChecked(t, f).GetResult(); got != tt.want {
				t.Errorf("result = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBudget(t *testing.T) {
	tests := []struct {
		name       string
		budget     uint32
		wantBudget uint32
		newErr     bool
	}{
		{"default", 0, DefaultBudget, false},
		{"one", 1, 1, false},
		{"max", MaxBudget, MaxBudget, false},
		{"over max", MaxBudget + 1, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, s := okServer(t)
			f, err := New(srv.URL, Options{AllowPrivate: true, Budget: tt.budget})
			if tt.newErr {
				if err == nil {
					t.Fatal("New: want error for a budget over the maximum")
				}
				return
			}
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if f.RequestBudget() != tt.wantBudget {
				t.Fatalf("RequestBudget = %d, want %d", f.RequestBudget(), tt.wantBudget)
			}
			for i := range tt.wantBudget {
				if _, err := f.Get(context.Background(), srv.URL+"/r"+strconv.Itoa(int(i)), ReasonSubresource); err != nil {
					t.Fatalf("request %d: %v", i+1, err)
				}
			}
			_, err = f.Get(context.Background(), srv.URL+"/over", ReasonSubresource)
			if !errors.Is(err, ErrRefused) {
				t.Fatalf("request %d: err = %v, want ErrRefused", tt.wantBudget+1, err)
			}
			if got := lastChecked(t, f).GetResult(); got != touchstonev1.CheckedLocation_RESULT_REFUSED {
				t.Errorf("result = %v, want RESULT_REFUSED", got)
			}
			if s.count() != int(tt.wantBudget) || f.RequestsUsed() != tt.wantBudget {
				t.Errorf("server saw %d, RequestsUsed %d; want %d", s.count(), f.RequestsUsed(), tt.wantBudget)
			}
		})
	}
}

func TestBudgetCountsRedirects(t *testing.T) {
	s := &seen{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.add(r)
		if r.URL.Path == "/a" {
			http.Redirect(w, r, "/b", http.StatusFound)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	f := mustNew(t, srv.URL+"/a", Options{AllowPrivate: true, Budget: 1})
	if _, err := f.Get(context.Background(), srv.URL+"/a", ReasonTarget); !errors.Is(err, ErrRefused) {
		t.Fatalf("Get: err = %v, want ErrRefused for the redirect hop over budget", err)
	}
	if s.count() != 1 {
		t.Errorf("server saw %d requests, want 1", s.count())
	}

	f = mustNew(t, srv.URL+"/a", Options{AllowPrivate: true, Budget: 2})
	resp, err := f.Get(context.Background(), srv.URL+"/a", ReasonTarget)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.URL != srv.URL+"/b" || f.RequestsUsed() != 2 {
		t.Errorf("URL = %s, RequestsUsed = %d; want %s/b, 2", resp.URL, f.RequestsUsed(), srv.URL)
	}
}

func TestSizeCap(t *testing.T) {
	const mib = 1 << 20
	tests := []struct {
		name  string
		sizes []int // body size of each successive request in one scan
		want  []touchstonev1.CheckedLocation_Result
	}{
		{"response at cap", []int{2 * mib}, []touchstonev1.CheckedLocation_Result{touchstonev1.CheckedLocation_RESULT_FOUND}},
		{"response over cap", []int{2*mib + 1}, []touchstonev1.CheckedLocation_Result{touchstonev1.CheckedLocation_RESULT_ERROR}},
		{
			"scan at cap then refused",
			[]int{2 * mib, 2 * mib, 2 * mib, 2 * mib, 2 * mib, 2 * mib, 2 * mib, 2 * mib, 2 * mib, 2 * mib, 1},
			[]touchstonev1.CheckedLocation_Result{
				touchstonev1.CheckedLocation_RESULT_FOUND, touchstonev1.CheckedLocation_RESULT_FOUND,
				touchstonev1.CheckedLocation_RESULT_FOUND, touchstonev1.CheckedLocation_RESULT_FOUND,
				touchstonev1.CheckedLocation_RESULT_FOUND, touchstonev1.CheckedLocation_RESULT_FOUND,
				touchstonev1.CheckedLocation_RESULT_FOUND, touchstonev1.CheckedLocation_RESULT_FOUND,
				touchstonev1.CheckedLocation_RESULT_FOUND, touchstonev1.CheckedLocation_RESULT_FOUND,
				touchstonev1.CheckedLocation_RESULT_REFUSED,
			},
		},
		{
			"response crossing scan cap",
			[]int{2 * mib, 2 * mib, 2 * mib, 2 * mib, 2 * mib, 2 * mib, 2 * mib, 2 * mib, 2 * mib, mib, 2 * mib},
			[]touchstonev1.CheckedLocation_Result{
				touchstonev1.CheckedLocation_RESULT_FOUND, touchstonev1.CheckedLocation_RESULT_FOUND,
				touchstonev1.CheckedLocation_RESULT_FOUND, touchstonev1.CheckedLocation_RESULT_FOUND,
				touchstonev1.CheckedLocation_RESULT_FOUND, touchstonev1.CheckedLocation_RESULT_FOUND,
				touchstonev1.CheckedLocation_RESULT_FOUND, touchstonev1.CheckedLocation_RESULT_FOUND,
				touchstonev1.CheckedLocation_RESULT_FOUND, touchstonev1.CheckedLocation_RESULT_FOUND,
				touchstonev1.CheckedLocation_RESULT_ERROR,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/"))
				w.Write(bytes.Repeat([]byte("a"), n))
			}))
			defer srv.Close()
			f := mustNew(t, srv.URL, Options{AllowPrivate: true})
			for i, n := range tt.sizes {
				resp, err := f.Get(context.Background(), srv.URL+"/"+strconv.Itoa(n), ReasonSubresource)
				got := lastChecked(t, f).GetResult()
				if got != tt.want[i] {
					t.Fatalf("request %d (%d bytes): result = %v, want %v (err %v)", i+1, n, got, tt.want[i], err)
				}
				if got == touchstonev1.CheckedLocation_RESULT_FOUND && len(resp.Body) != n {
					t.Fatalf("request %d: body is %d bytes, want %d", i+1, len(resp.Body), n)
				}
				if got != touchstonev1.CheckedLocation_RESULT_FOUND && err == nil {
					t.Fatalf("request %d: want error", i+1)
				}
			}
		})
	}
}

func TestTimeout(t *testing.T) {
	if RequestTimeout != 10*time.Second {
		t.Fatalf("RequestTimeout = %v, want 10s", RequestTimeout)
	}
	tests := []struct {
		name  string
		delay time.Duration
		want  touchstonev1.CheckedLocation_Result
	}{
		{"within timeout", 0, touchstonev1.CheckedLocation_RESULT_FOUND},
		{"slow headers", time.Second, touchstonev1.CheckedLocation_RESULT_ERROR},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case <-time.After(tt.delay):
				case <-r.Context().Done():
				}
				fmt.Fprint(w, "ok")
			}))
			defer srv.Close()
			f := mustNew(t, srv.URL, Options{AllowPrivate: true})
			f.timeout = 100 * time.Millisecond
			_, err := f.Get(context.Background(), srv.URL, ReasonTarget)
			if got := lastChecked(t, f).GetResult(); got != tt.want {
				t.Fatalf("result = %v, want %v (err %v)", got, tt.want, err)
			}
			if tt.want == touchstonev1.CheckedLocation_RESULT_ERROR && !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("err = %v, want a deadline error", err)
			}
		})
	}
}

// fakeResolver maps host names to addresses without touching DNS.
type fakeResolver map[string][]netip.Addr

func (r fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if ips, ok := r[host]; ok {
		return ips, nil
	}
	return nil, fmt.Errorf("fakeResolver: no such host %q", host)
}

func TestSSRFGuard(t *testing.T) {
	srv, s := okServer(t)
	port := strings.TrimPrefix(srv.URL, "http://127.0.0.1:")
	resolver := fakeResolver{
		"intranet.test": {netip.MustParseAddr("10.1.2.3")},
		"loopback.test": {netip.MustParseAddr("127.0.0.1")},
	}
	tests := []struct {
		name string
		url  string
	}{
		{"loopback", srv.URL + "/"},
		{"loopback other", "http://127.8.9.10:" + port + "/"},
		{"rfc1918 10/8", "http://10.0.0.1/"},
		{"rfc1918 172.16/12", "http://172.16.5.4/"},
		{"rfc1918 192.168/16", "http://192.168.1.1/"},
		{"link-local metadata", "http://169.254.169.254/latest/meta-data/"},
		{"cgnat", "http://100.64.0.1/"},
		{"unspecified", "http://0.0.0.0:" + port + "/"},
		{"ipv6 loopback", "http://[::1]:" + port + "/"},
		{"ipv4-mapped loopback", "http://[::ffff:127.0.0.1]:" + port + "/"},
		{"ipv6 ula fc00", "http://[fc00::1]/"},
		{"ipv6 ula fd00", "http://[fd12:3456::1]/"},
		{"hostname resolving to private", "http://intranet.test/"},
		{"hostname resolving to loopback", "http://loopback.test:" + port + "/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := mustNew(t, tt.url, Options{Resolver: resolver})
			before := s.count()
			_, err := f.Get(context.Background(), tt.url, ReasonTarget)
			if !errors.Is(err, ErrRefused) {
				t.Fatalf("Get(%s): err = %v, want ErrRefused", tt.url, err)
			}
			if got := lastChecked(t, f).GetResult(); got != touchstonev1.CheckedLocation_RESULT_REFUSED {
				t.Errorf("result = %v, want RESULT_REFUSED", got)
			}
			if s.count() != before {
				t.Error("request reached the loopback server")
			}
		})
	}
}

func TestSSRFGuardRefusesRedirectToPrivate(t *testing.T) {
	for _, dest := range []string{"http://169.254.169.254/latest/meta-data/", "http://10.0.0.1/", "http://intranet.test/"} {
		t.Run(dest, func(t *testing.T) {
			srv := httptest.NewServer(http.RedirectHandler(dest, http.StatusFound))
			defer srv.Close()
			f := mustNew(t, srv.URL, Options{Resolver: fakeResolver{"intranet.test": {netip.MustParseAddr("192.168.0.10")}}})
			// Let only the test server's own address through, so the
			// redirect is what the guard has to catch.
			serverAddr := netip.MustParseAddrPort(strings.TrimPrefix(srv.URL, "http://")).Addr()
			f.blocked = func(ip netip.Addr) bool { return ip != serverAddr && IsPrivate(ip) }

			_, err := f.Get(context.Background(), srv.URL, ReasonTarget)
			if !errors.Is(err, ErrRefused) {
				t.Fatalf("Get: err = %v, want ErrRefused", err)
			}
			if got := lastChecked(t, f).GetResult(); got != touchstonev1.CheckedLocation_RESULT_REFUSED {
				t.Errorf("result = %v, want RESULT_REFUSED", got)
			}
		})
	}
}

func TestAllowPrivate(t *testing.T) {
	srv, s := okServer(t)
	f := mustNew(t, srv.URL, Options{AllowPrivate: true})
	if _, err := f.Get(context.Background(), srv.URL, ReasonTarget); err != nil {
		t.Fatalf("Get with AllowPrivate: %v", err)
	}
	if s.count() != 1 {
		t.Errorf("server saw %d requests, want 1", s.count())
	}
}

func TestIsPrivate(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"10.255.255.255", true},
		{"172.31.0.1", true},
		{"172.32.0.1", false},
		{"192.168.0.1", true},
		{"169.254.169.254", true},
		{"100.64.0.1", true},
		{"100.127.255.255", true},
		{"100.128.0.1", false},
		{"0.0.0.0", true},
		{"224.0.0.1", true},
		{"::1", true},
		{"::", true},
		{"fc00::1", true},
		{"fdff::1", true},
		{"fe80::1", true},
		{"::ffff:10.0.0.1", true},
		{"8.8.8.8", false},
		{"93.184.216.34", false},
		{"2606:4700:4700::1111", false},
	}
	for _, tt := range tests {
		if got := IsPrivate(netip.MustParseAddr(tt.ip)); got != tt.want {
			t.Errorf("IsPrivate(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestNewRejectsBadTarget(t *testing.T) {
	for _, target := range []string{"", "example.com", "ftp://example.com/", "http://"} {
		if _, err := New(target, Options{}); err == nil {
			t.Errorf("New(%q): want error", target)
		}
	}
}
