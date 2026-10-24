package vuln

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// fixtureServer serves one file from testdata for every request and records
// each request's method, path and query. The fixtures are in the wire shape
// of the feeds, but their values are illustrative, not recorded responses.
func fixtureServer(t *testing.T, file string) (*httptest.Server, *requestLog) {
	t.Helper()
	log := &requestLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r)
		b, err := os.ReadFile(filepath.Join("testdata", file))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return srv, log
}

// requestLog counts requests a test server received.
type requestLog struct {
	mu   sync.Mutex
	reqs []*http.Request
}

func (l *requestLog) add(r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reqs = append(l.reqs, r)
}

func (l *requestLog) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.reqs)
}
