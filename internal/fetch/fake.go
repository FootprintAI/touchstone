package fetch

import (
	"context"
	"fmt"
)

// Call records one Get invocation made against a Fake.
type Call struct {
	URL    string
	Reason Reason
}

// Fake is an in-memory Fetcher for tests: it serves canned responses by
// URL and records every call it receives so a test can assert exactly
// what was fetched and why.
type Fake struct {
	Responses map[string]*Response
	Errors    map[string]error
	Calls     []Call
}

// NewFake returns a Fake with no responses configured.
func NewFake() *Fake {
	return &Fake{
		Responses: make(map[string]*Response),
		Errors:    make(map[string]error),
	}
}

// SetResponse configures the Response returned for a URL regardless of
// reason.
func (f *Fake) SetResponse(url string, resp *Response) {
	f.Responses[url] = resp
}

// SetError configures the error returned for a URL regardless of reason.
func (f *Fake) SetError(url string, err error) {
	f.Errors[url] = err
}

func (f *Fake) Get(_ context.Context, url string, reason Reason) (*Response, error) {
	f.Calls = append(f.Calls, Call{URL: url, Reason: reason})
	if err, ok := f.Errors[url]; ok {
		return nil, err
	}
	if resp, ok := f.Responses[url]; ok {
		return resp, nil
	}
	return nil, fmt.Errorf("fetch: fake has no response configured for %q", url)
}
