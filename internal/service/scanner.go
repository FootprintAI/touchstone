package service

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	touchstonev1 "github.com/FootprintAI/touchstone/gen/go/touchstone/v1"
	"github.com/FootprintAI/touchstone/internal/discover"
	"github.com/FootprintAI/touchstone/internal/fetch"
	"github.com/FootprintAI/touchstone/internal/fingerprint"
	"github.com/FootprintAI/touchstone/internal/pipeline"
	"github.com/FootprintAI/touchstone/internal/sbom"
	"github.com/FootprintAI/touchstone/internal/vuln"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Scanner is the ScanService. It fetches the target page and the scripts
// it loads through a PassiveFetcher and fingerprints them, discovers
// vendor-published evidence (security.txt, CSAF VEX, TEA, repo links),
// reads the reviewer-supplied SBOM/VEX if any, looks each component up
// through vuln.Matcher (OSV by purl, NVD by CPE, enriched with KEV and
// EPSS), and returns the report. Components are listed highest tier first
// and merged by key; conflict recording comes in a later slice.
type Scanner struct {
	touchstonev1.UnimplementedScanServiceServer

	// Fetch carries the settings that are not per request: AllowPrivate
	// (CLI only) and Version. The request budget comes from each
	// ScanRequest.
	Fetch fetch.Options

	// Vulns looks components up and ranks their vulnerabilities.
	Vulns *vuln.Matcher

	// Now returns the scan's start and completion time; time.Now if nil.
	Now func() time.Time
}

var _ touchstonev1.ScanServiceServer = (*Scanner)(nil)

// Scan runs one scan. A target that cannot be fetched is not an RPC error:
// the report says TARGET_UNREACHABLE and lists the attempt in checked.
func (s *Scanner) Scan(ctx context.Context, req *touchstonev1.ScanRequest) (*touchstonev1.ScanReport, error) {
	target, err := absoluteURL(req.GetUrl())
	if err != nil {
		return nil, err
	}
	opts := s.Fetch
	opts.Budget = req.GetRequestBudget()
	if raw := req.GetSbomUrl(); raw != "" {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, status.Errorf(codes.InvalidArgument, "sbom_url must be an absolute http(s) URL, got %q", raw)
		}
		opts.SuppliedURL = raw
	}
	f, err := fetch.New(target.String(), opts)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	rep := &touchstonev1.ScanReport{
		SchemaVersion: "1",
		TargetUrl:     target.String(),
		ToolVersion:   ToolVersion,
		StartedAt:     timestamppb.New(now().UTC()),
		RequestBudget: f.RequestBudget(),
		Disclaimer:    Disclaimer,
	}

	page, err := f.Get(ctx, target.String(), fetch.ReasonTarget)
	if err != nil {
		rep.ScanStatus = touchstonev1.ScanStatus_SCAN_STATUS_TARGET_UNREACHABLE
		s.finish(rep, f, now)
		return rep, nil
	}
	rep.ScanStatus = touchstonev1.ScanStatus_SCAN_STATUS_OK

	fingerprinted, fpErr := collect(ctx, f, page)
	rep.Sources = append(rep.Sources, &touchstonev1.SourceStatus{
		Source: "fingerprint",
		Ok:     fpErr == nil,
		Error:  errText(fpErr),
	})

	var discovered []pipeline.Component
	found, discErr := discover.Discover(ctx, f, target.String(), page)
	if found != nil {
		discovered = found.Components
	}
	rep.Sources = append(rep.Sources, &touchstonev1.SourceStatus{
		Source: "discover",
		Ok:     discErr == nil,
		Error:  errText(discErr),
	})

	var given []pipeline.Component
	if req.GetSbomUrl() != "" || len(req.GetSbomDocument()) > 0 {
		var supErr error
		given, supErr = supplied(ctx, f, req)
		rep.Sources = append(rep.Sources, &touchstonev1.SourceStatus{
			Source: "supplied",
			Ok:     supErr == nil,
			Error:  errText(supErr),
		})
	}

	// Highest tier first: merge keeps the first component's confidence.
	comps := merge(slices.Concat(given, discovered, fingerprinted))
	rep.LookupStatus, rep.Components = s.lookup(ctx, rep, comps)
	s.finish(rep, f, now)
	return rep, nil
}

// collect fingerprints the target page's headers and the scripts it
// references. Each script is fetched as SUBRESOURCE, as a browser would
// load it, and only a 2xx script counts as loaded.
func collect(ctx context.Context, f fetch.Fetcher, page *fetch.Response) ([]pipeline.Component, error) {
	comps := fingerprint.FromHeaders(page.URL, page.Header)
	pageURL, err := url.Parse(page.URL)
	if err != nil {
		return comps, err
	}
	scripts, err := fingerprint.ScriptURLs(pageURL, page.Body)
	if err != nil {
		return comps, err
	}
	var errs []error
	for _, src := range scripts {
		resp, err := f.Get(ctx, src, fetch.ReasonSubresource)
		if err != nil {
			// The refusal or failure is already in the checked list.
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			continue
		}
		found, err := fingerprint.FromURL(src)
		if err != nil {
			errs = append(errs, err)
		}
		if len(found) == 0 {
			// Content is matched only when the URL names no library, so one
			// script yields at most one match per library.
			found, err = fingerprint.FromContent(src, resp.Body)
			if err != nil {
				errs = append(errs, err)
			}
		}
		comps = append(comps, found...)
	}
	return merge(comps), errors.Join(errs...)
}

// supplied reads the reviewer's own SBOM/VEX (decision D1): the uploaded
// document, and the one at sbom_url fetched as SUPPLIED. Its components
// are High confidence with SBOM_SUPPLIED evidence.
func supplied(ctx context.Context, f fetch.Fetcher, req *touchstonev1.ScanRequest) ([]pipeline.Component, error) {
	var comps []pipeline.Component
	var errs []error
	read := func(location string, data []byte) {
		doc, err := sbom.Parse(data)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", location, err))
			return
		}
		for _, c := range doc.Components {
			comps = append(comps, pipeline.Component{
				Name:       c.Name,
				Version:    c.Version,
				Purl:       c.Purl,
				CPE:        c.CPE,
				Confidence: "HIGH",
				Evidence:   []pipeline.Evidence{{Kind: "SBOM_SUPPLIED", Location: location, Detail: string(doc.Format)}},
			})
		}
	}
	if doc := req.GetSbomDocument(); len(doc) > 0 {
		read(UploadedLocation, doc)
	}
	if u := req.GetSbomUrl(); u != "" {
		resp, err := f.Get(ctx, u, fetch.ReasonSupplied)
		switch {
		case err != nil:
			errs = append(errs, err)
		case resp.StatusCode < 200 || resp.StatusCode >= 300:
			errs = append(errs, fmt.Errorf("%s: HTTP %d", u, resp.StatusCode))
		default:
			read(u, resp.Body)
		}
	}
	return comps, errors.Join(errs...)
}

// UploadedLocation is the evidence location of a component read from an
// uploaded SBOM/VEX document, which has no URL.
const UploadedLocation = "uploaded SBOM/VEX document"

// lookup asks the Matcher about every component (by purl, else CPE) and
// converts the components, with their ranked vulnerabilities, to proto.
// It returns the lookup status, which is COMPLETE only if every lookup
// and enrichment succeeded.
func (s *Scanner) lookup(ctx context.Context, rep *touchstonev1.ScanReport, comps []pipeline.Component) (touchstonev1.LookupStatus, []*touchstonev1.Component) {
	queries := make([]vuln.Query, len(comps))
	for i, c := range comps {
		queries[i] = vuln.Query{Purl: c.Purl, CPE: c.CPE}
	}
	res := s.Vulns.Match(ctx, queries)
	for _, st := range res.Sources {
		rep.Sources = append(rep.Sources, &touchstonev1.SourceStatus{Source: st.Source, Ok: st.OK, Error: st.Error})
	}
	out := make([]*touchstonev1.Component, len(comps))
	for i, c := range comps {
		out[i] = toProto(c, res.Matches[i])
	}
	switch res.Status {
	case vuln.StatusComplete:
		return touchstonev1.LookupStatus_LOOKUP_STATUS_COMPLETE, out
	case vuln.StatusPartial:
		return touchstonev1.LookupStatus_LOOKUP_STATUS_PARTIAL, out
	default:
		return touchstonev1.LookupStatus_LOOKUP_STATUS_FAILED, out
	}
}

// finish fills in the request accounting and the completion time.
func (s *Scanner) finish(rep *touchstonev1.ScanReport, f *fetch.PassiveFetcher, now func() time.Time) {
	rep.Checked = f.Checked()
	rep.RequestsUsed = f.RequestsUsed()
	rep.CompletedAt = timestamppb.New(now().UTC())
}

// merge combines components that share a key (purl, else name): the same
// library loaded twice is one component with both evidence items.
func merge(comps []pipeline.Component) []pipeline.Component {
	var out []pipeline.Component
	index := map[string]int{}
	for _, c := range comps {
		key := c.Purl
		if key == "" {
			key = c.Name
		}
		i, seen := index[key]
		if !seen {
			index[key] = len(out)
			out = append(out, c)
			continue
		}
		out[i].Evidence = append(out[i].Evidence, c.Evidence...)
		for _, caveat := range c.Caveats {
			if !contains(out[i].Caveats, caveat) {
				out[i].Caveats = append(out[i].Caveats, caveat)
			}
		}
	}
	return out
}

// toProto converts one component. The pipeline's Confidence and Kind
// strings are the proto enum names without their type prefix.
func toProto(c pipeline.Component, matches []vuln.Match) *touchstonev1.Component {
	out := &touchstonev1.Component{
		Name:       c.Name,
		Version:    c.Version,
		Purl:       c.Purl,
		Cpe:        c.CPE,
		Confidence: touchstonev1.Confidence(touchstonev1.Confidence_value["CONFIDENCE_"+c.Confidence]),
		Caveats:    c.Caveats,
	}
	for _, e := range c.Evidence {
		out.Evidence = append(out.Evidence, &touchstonev1.Evidence{
			Kind:     touchstonev1.EvidenceKind(touchstonev1.EvidenceKind_value["EVIDENCE_KIND_"+e.Kind]),
			Location: e.Location,
			Detail:   e.Detail,
		})
	}
	for _, m := range matches {
		out.Vulnerabilities = append(out.Vulnerabilities, &touchstonev1.Vulnerability{
			Id:       m.ID,
			Aliases:  m.Aliases,
			Summary:  m.Summary,
			Kev:      m.KEV,
			Epss:     m.EPSS,
			CvssBase: m.CVSSBase,
		})
	}
	return out
}

func absoluteURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, status.Errorf(codes.InvalidArgument, "url must be an absolute http(s) URL, got %q", raw)
	}
	return u, nil
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return strings.TrimSpace(err.Error())
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
