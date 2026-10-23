// Package service implements touchstone.v1.ScanService. In slice S0 it is
// a stub: Scan returns a canned ScanReport so the CLI, the gateway and the
// web page can be built against the contract before the pipeline exists
// (see docs/architecture/touchstone.md, "Delivery slices").
package service

import (
	"context"
	"net/url"
	"time"

	touchstonev1 "github.com/FootprintAI/touchstone/gen/go/touchstone/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ToolVersion is reported in every ScanReport.
const ToolVersion = "0.0.0-dev"

// Disclaimer is reported in every ScanReport.
const Disclaimer = "Touchstone reports publicly observable evidence only. " +
	"Findings are graded by confidence and are not proof that a vulnerability is exploitable."

const defaultRequestBudget = 50

// Stub is a ScanService that returns a canned report for any valid URL
// without contacting it.
type Stub struct {
	touchstonev1.UnimplementedScanServiceServer

	// Now returns the scan's start and completion time; time.Now if nil.
	Now func() time.Time
}

var _ touchstonev1.ScanServiceServer = (*Stub)(nil)

// Scan validates req.Url and returns a canned report for it.
func (s *Stub) Scan(_ context.Context, req *touchstonev1.ScanRequest) (*touchstonev1.ScanReport, error) {
	u, err := url.Parse(req.GetUrl())
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, status.Errorf(codes.InvalidArgument, "url must be an absolute http(s) URL, got %q", req.GetUrl())
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	budget := req.GetRequestBudget()
	if budget == 0 {
		budget = defaultRequestBudget
	}
	return CannedReport(u.String(), budget, now()), nil
}

// CannedReport is the fixed report the stub returns: one Low-confidence
// fingerprinted component with one vulnerability. Nothing is fetched, so
// checked is empty and requests_used is 0; the component
// carries a CANNED_STUB_REPORT caveat so the output can't be mistaken
// for a real finding.
func CannedReport(targetURL string, budget uint32, at time.Time) *touchstonev1.ScanReport {
	ts := timestamppb.New(at.UTC())
	epss := 0.0123
	cvss := 6.1
	return &touchstonev1.ScanReport{
		SchemaVersion: "1",
		TargetUrl:     targetURL,
		ScanStatus:    touchstonev1.ScanStatus_SCAN_STATUS_OK,
		LookupStatus:  touchstonev1.LookupStatus_LOOKUP_STATUS_COMPLETE,
		StartedAt:     ts,
		CompletedAt:   ts,
		ToolVersion:   ToolVersion,
		VulnDataAsOf:  ts,
		Components: []*touchstonev1.Component{{
			Name:       "jquery",
			Version:    "1.12.4",
			Purl:       "pkg:npm/jquery@1.12.4",
			Confidence: touchstonev1.Confidence_CONFIDENCE_LOW,
			Evidence: []*touchstonev1.Evidence{{
				Kind:     touchstonev1.EvidenceKind_EVIDENCE_KIND_FINGERPRINT_ASSET,
				Location: targetURL,
				Detail:   "jquery-1.12.4.min.js",
			}},
			Caveats: []string{"CANNED_STUB_REPORT"},
			Vulnerabilities: []*touchstonev1.Vulnerability{{
				Id:        "CVE-2020-11022",
				Aliases:   []string{"GHSA-gxr4-xjj5-5px2"},
				Summary:   "Potential XSS vulnerability in jQuery.htmlPrefilter",
				Epss:      &epss,
				CvssBase:  &cvss,
				VexStatus: touchstonev1.VexStatus_VEX_STATUS_UNSPECIFIED,
			}},
		}},
		RequestBudget: budget,
		Sources: []*touchstonev1.SourceStatus{
			{Source: "stub", Ok: true},
		},
		Disclaimer: Disclaimer,
	}
}
