package service

import (
	"context"
	"errors"
	"fmt"
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

// Scanner is the ScanService. It fetches the target page and the scripts it
// loads through a PassiveFetcher, fingerprints them, matches each component
// against the vulnerability sources, and returns the report. Merging across
// tiers comes in a later slice.
type Scanner struct {
	touchstonev1.UnimplementedScanServiceServer

	// Fetch carries the settings that are not per request: AllowPrivate
	// (CLI only) and Version. The request budget comes from each
	// ScanRequest.
	Fetch fetch.Options

	// Vulns looks components up by purl (OSV in the CLI).
	Vulns vuln.Source

	// CPE looks components that have a CPE but no purl up (NVD in the CLI).
	// CPEMax caps the lookups one scan makes (vuln.NVDMaxLookups); components
	// past the cap are reported as not looked up.
	CPE    vuln.Source
	CPEMax int

	// KEV and EPSS enrich every CVE the lookups found.
	KEV  vuln.Enricher
	EPSS vuln.Enricher

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

// lookup matches every component against the vulnerability sources and
// converts the components to proto. A component with a purl goes to Vulns;
// one with only a CPE goes to CPE, up to CPEMax lookups. Every CVE found is
// enriched with KEV and EPSS, and each component's findings are ranked. Each
// source that was asked anything gets a SourceStatus. The lookup status is
// COMPLETE only if every question was answered.
func (s *Scanner) lookup(ctx context.Context, rep *touchstonev1.ScanReport, comps []pipeline.Component) (touchstonev1.LookupStatus, []*touchstonev1.Component) {
	osv := &tally{name: s.Vulns.Name()}
	nvd := &tally{name: s.CPE.Name()}
	kev := &tally{name: s.KEV.Name()}
	epss := &tally{name: s.EPSS.Name()}

	findings := make([][]vuln.Finding, len(comps))
	var cpeLookups, capped int
	for i, c := range comps {
		switch {
		case c.Purl != "":
			f, err := s.Vulns.Lookup(ctx, []vuln.Query{{Purl: c.Purl}})
			osv.answer(err)
			findings[i] = f
		case c.CPE != "":
			if cpeLookups >= s.CPEMax {
				capped++
				continue
			}
			cpeLookups++
			f, err := s.CPE.Lookup(ctx, []vuln.Query{{CPE: c.CPE}})
			nvd.answer(err)
			findings[i] = f
		}
	}
	if capped > 0 {
		nvd.skip(capped, fmt.Errorf("capped at %d CPE lookups per scan, %d components not looked up (NVD_API_KEY raises the cap)", s.CPEMax, capped))
	}

	var ids []string
	for _, fs := range findings {
		for _, f := range fs {
			ids = append(ids, f.ID)
		}
	}
	var kevs, epsss map[string]vuln.Enrichment
	if len(ids) > 0 {
		var err error
		kevs, err = s.KEV.Enrich(ctx, ids)
		kev.answer(err)
		epsss, err = s.EPSS.Enrich(ctx, ids)
		epss.answer(err)
	}

	var out []*touchstonev1.Component
	for i, c := range comps {
		vuln.Apply(findings[i], kevs, epsss)
		vuln.Rank(findings[i])
		out = append(out, toProto(c, findings[i]))
	}
	for _, t := range []*tally{osv, nvd, kev, epss} {
		if t.asked > 0 {
			rep.Sources = append(rep.Sources, t.status())
		}
	}
	return lookupStatus(osv, nvd, kev, epss), out
}

// tally counts the questions one source was asked and the ones it failed to
// answer.
type tally struct {
	name   string
	asked  int
	failed int
	errs   []error
}

// answer records one question, failed if err is not nil.
func (t *tally) answer(err error) {
	t.asked++
	if err != nil {
		t.failed++
		t.errs = append(t.errs, err)
	}
}

// skip records n questions the source was never asked, because a limit
// stopped them, as failed with the reason.
func (t *tally) skip(n int, err error) {
	t.asked += n
	t.failed += n
	t.errs = append(t.errs, err)
}

func (t *tally) status() *touchstonev1.SourceStatus {
	return &touchstonev1.SourceStatus{
		Source: t.name,
		Ok:     t.failed == 0,
		Error:  errText(errors.Join(t.errs...)),
	}
}

// lookupStatus is COMPLETE when no question failed, FAILED when every question
// failed, and PARTIAL when some did. A scan that asked nothing is COMPLETE.
func lookupStatus(ts ...*tally) touchstonev1.LookupStatus {
	var asked, failed int
	for _, t := range ts {
		asked += t.asked
		failed += t.failed
	}
	switch {
	case failed == 0:
		return touchstonev1.LookupStatus_LOOKUP_STATUS_COMPLETE
	case failed == asked:
		return touchstonev1.LookupStatus_LOOKUP_STATUS_FAILED
	default:
		return touchstonev1.LookupStatus_LOOKUP_STATUS_PARTIAL
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
			Id:       f.ID,
			Aliases:  f.Aliases,
			Summary:  f.Summary,
			Kev:      f.KEV,
			Epss:     f.EPSS,
			CvssBase: f.CVSSBase,
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
