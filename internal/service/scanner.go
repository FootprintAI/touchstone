package service

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	touchstonev1 "github.com/FootprintAI/touchstone/gen/go/touchstone/v1"
	"github.com/FootprintAI/touchstone/internal/fetch"
	"github.com/FootprintAI/touchstone/internal/fingerprint"
	"github.com/FootprintAI/touchstone/internal/pipeline"
	"github.com/FootprintAI/touchstone/internal/vuln"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Scanner is the walking-skeleton ScanService (slice S2). It fetches the
// target page and the scripts it loads through a PassiveFetcher,
// fingerprints them, looks each purl up through vuln.Source, and returns
// the report. Merging across tiers and the NVD, KEV and EPSS lookups come
// in later slices.
type Scanner struct {
	touchstonev1.UnimplementedScanServiceServer

	// Fetch carries the settings that are not per request: AllowPrivate
	// (CLI only) and Version. The request budget comes from each
	// ScanRequest.
	Fetch fetch.Options

	// Vulns looks components up by purl (OSV in the CLI).
	Vulns vuln.Source

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

	comps, fpErr := collect(ctx, f, page)
	rep.Sources = append(rep.Sources, &touchstonev1.SourceStatus{
		Source: "fingerprint",
		Ok:     fpErr == nil,
		Error:  errText(fpErr),
	})

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
		comps = append(comps, found...)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return merge(comps), errors.Join(errs...)
}

// lookup asks vuln.Source about every component that has a purl and
// converts the components to proto. It returns the lookup status, which is
// COMPLETE only if every lookup succeeded.
func (s *Scanner) lookup(ctx context.Context, rep *touchstonev1.ScanReport, comps []pipeline.Component) (touchstonev1.LookupStatus, []*touchstonev1.Component) {
	var out []*touchstonev1.Component
	var ok, failed int
	var errs []error
	for _, c := range comps {
		var findings []vuln.Finding
		if c.Purl != "" {
			var err error
			findings, err = s.Vulns.Lookup(ctx, []vuln.Query{{Purl: c.Purl}})
			if err != nil {
				failed++
				errs = append(errs, err)
			} else {
				ok++
			}
		}
		out = append(out, toProto(c, findings))
	}
	if ok+failed > 0 {
		rep.Sources = append(rep.Sources, &touchstonev1.SourceStatus{
			Source: s.Vulns.Name(),
			Ok:     failed == 0,
			Error:  errText(errors.Join(errs...)),
		})
	}
	switch {
	case failed == 0:
		return touchstonev1.LookupStatus_LOOKUP_STATUS_COMPLETE, out
	case ok > 0:
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
func toProto(c pipeline.Component, findings []vuln.Finding) *touchstonev1.Component {
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
	for _, f := range findings {
		out.Vulnerabilities = append(out.Vulnerabilities, &touchstonev1.Vulnerability{
			Id:      f.ID,
			Aliases: f.Aliases,
			Summary: f.Summary,
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
