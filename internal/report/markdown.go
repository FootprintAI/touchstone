// Package report renders a touchstone.v1.ScanReport for people. JSON is
// protojson of the proto and needs no code here; Markdown is rendered by
// this package so a report can be pasted into a vendor-review ticket.
//
// Every string that originates outside Touchstone (the URL the user typed,
// vendor pages, SBOMs, repos, vulnerability feeds) passes through escape
// before it reaches the Markdown, so a hostile component name or evidence
// string cannot inject Markdown or HTML into the ticket it is pasted in.
package report

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode"

	touchstonev1 "github.com/FootprintAI/touchstone/gen/go/touchstone/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Disclaimer is the fixed text carried by every ScanReport and printed in
// every Markdown report. It is a constant here, not something read from
// the report, so a report can never be rendered without it.
const Disclaimer = "Touchstone reports publicly observable evidence only. " +
	"Findings are graded by confidence and are not proof that a vulnerability is exploitable. " +
	"Low-confidence findings are inferred from passive fingerprints and are unverified."

// unknown stands in for metadata the report does not carry, so the
// metadata lines are present in every rendering.
const unknown = "unknown"

// Markdown renders r as a Markdown document.
func Markdown(r *touchstonev1.ScanReport) string {
	var b strings.Builder
	_ = WriteMarkdown(&b, r)
	return b.String()
}

// WriteMarkdown renders r as a Markdown document to w.
func WriteMarkdown(w io.Writer, r *touchstonev1.ScanReport) error {
	m := &markdown{w: w, complete: r.GetLookupStatus() == touchstonev1.LookupStatus_LOOKUP_STATUS_COMPLETE}
	m.header(r)
	m.components(r)
	m.conflicts(r.GetConflicts())
	m.checked(r.GetChecked())
	m.sources(r.GetSources())
	return m.err
}

type markdown struct {
	w        io.Writer
	err      error
	complete bool // lookup_status == COMPLETE; counts are rendered only then
}

func (m *markdown) printf(format string, args ...any) {
	if m.err != nil {
		return
	}
	_, m.err = fmt.Fprintf(m.w, format, args...)
}

func (m *markdown) header(r *touchstonev1.ScanReport) {
	m.printf("# Touchstone scan report\n\n")
	m.printf("- **Target:** %s\n", orUnknown(escape(r.GetTargetUrl())))
	m.printf("- **Scan status:** %s\n", scanStatus(r.GetScanStatus()))
	m.printf("- **Started:** %s\n", timestamp(r.GetStartedAt()))
	m.printf("- **Completed:** %s\n", timestamp(r.GetCompletedAt()))
	m.printf("- **Tool version:** %s\n", orUnknown(escape(r.GetToolVersion())))
	m.printf("- **Vulnerability data as of:** %s\n", timestamp(r.GetVulnDataAsOf()))
	m.printf("- **Vulnerability lookup:** %s\n", lookupStatus(r.GetLookupStatus()))
	m.printf("- **Requests used:** %d of %d\n", r.GetRequestsUsed(), r.GetRequestBudget())
	m.printf("- **Schema version:** %s\n", orUnknown(escape(r.GetSchemaVersion())))
	m.printf("\n> **Disclaimer.** %s\n", Disclaimer)
}

// tiers lists the confidence tiers in the order they are rendered, with
// the meaning each one has in the PRD.
var tiers = []struct {
	confidence touchstonev1.Confidence
	heading    string
}{
	{touchstonev1.Confidence_CONFIDENCE_HIGH, "High confidence (declared by the vendor in an SBOM or VEX)"},
	{touchstonev1.Confidence_CONFIDENCE_MEDIUM, "Medium confidence (public source repo at its latest release; may differ from what is deployed)"},
	{touchstonev1.Confidence_CONFIDENCE_LOW, "Low confidence (passive fingerprint; inferred and unverified)"},
	{touchstonev1.Confidence_CONFIDENCE_UNSPECIFIED, "Unspecified confidence"},
}

func (m *markdown) components(r *touchstonev1.ScanReport) {
	m.printf("\n## Components\n")
	if r.GetScanStatus() == touchstonev1.ScanStatus_SCAN_STATUS_TARGET_UNREACHABLE {
		m.printf("\nThe target could not be fetched, so no components were detected.\n")
		return
	}
	if len(r.GetComponents()) == 0 {
		m.printf("\nNo components were detected.\n")
		return
	}
	for _, tier := range tiers {
		var cs []*touchstonev1.Component
		for _, c := range r.GetComponents() {
			if c.GetConfidence() == tier.confidence {
				cs = append(cs, c)
			}
		}
		if len(cs) == 0 {
			continue
		}
		m.printf("\n### %s\n", tier.heading)
		for _, c := range cs {
			m.component(c)
		}
	}
}

func (m *markdown) component(c *touchstonev1.Component) {
	name := orUnknown(escape(c.GetName()))
	if v := escape(c.GetVersion()); v != "" {
		name += " " + v
	}
	m.printf("\n#### %s\n\n", name)
	if c.GetPurl() != "" {
		m.printf("- **purl:** %s\n", escape(c.GetPurl()))
	}
	if c.GetCpe() != "" {
		m.printf("- **CPE:** %s\n", escape(c.GetCpe()))
	}
	if len(c.GetCaveats()) > 0 {
		m.printf("- **Caveats:** %s\n", escapeJoin(c.GetCaveats()))
	}
	m.printf("- **Evidence:**\n")
	m.evidence(c.GetEvidence())
	m.vulnerabilities(c.GetVulnerabilities())
}

func (m *markdown) evidence(es []*touchstonev1.Evidence) {
	if len(es) == 0 {
		m.printf("  - none recorded\n")
		return
	}
	for _, e := range es {
		m.printf("  - %s: %s", enumLabel(e.GetKind().String(), "EVIDENCE_KIND_"), orUnknown(escape(e.GetLocation())))
		if e.GetDetail() != "" {
			m.printf(" (%s)", escape(e.GetDetail()))
		}
		m.printf("\n")
	}
}

// vulnerabilities renders the vulnerability table. A count ("2
// vulnerabilities", "no known vulnerabilities") appears only when the
// lookup completed; otherwise the heading says "lookup incomplete", so an
// empty table can never read as a clean bill of health.
func (m *markdown) vulnerabilities(vs []*touchstonev1.Vulnerability) {
	var shown, suppressed []*touchstonev1.Vulnerability
	for _, v := range vs {
		if v.GetSuppressed() {
			suppressed = append(suppressed, v)
		} else {
			shown = append(shown, v)
		}
	}
	switch {
	case !m.complete:
		m.printf("- **Vulnerabilities:** lookup incomplete\n")
	case len(shown) == 0:
		m.printf("- **Vulnerabilities:** no known vulnerabilities\n")
	default:
		m.printf("- **Vulnerabilities:** %s\n", plural(len(shown), "vulnerability", "vulnerabilities"))
	}
	if len(shown) > 0 {
		m.printf("\n| ID | Aliases | KEV | EPSS | CVSS | VEX | Summary |\n|---|---|---|---|---|---|---|\n")
		for _, v := range shown {
			m.printf("| %s | %s | %s | %s | %s | %s | %s |\n",
				orUnknown(escape(v.GetId())), escapeJoin(v.GetAliases()), yesNo(v.GetKev()),
				score(v.Epss), score(v.CvssBase), vexStatus(v), escape(v.GetSummary()))
		}
	}
	if len(suppressed) > 0 {
		if len(shown) > 0 {
			m.printf("\n") // close the table before the next list
		}
		m.printf("- **Suppressed by VEX:**\n")
		for _, v := range suppressed {
			m.printf("  - %s: %s", orUnknown(escape(v.GetId())), vexStatus(v))
			if v.GetVexJustification() != "" {
				m.printf(" (%s)", escape(v.GetVexJustification()))
			}
			m.printf("\n")
		}
	}
}

func (m *markdown) conflicts(cs []*touchstonev1.Conflict) {
	if len(cs) == 0 {
		return
	}
	m.printf("\n## Version conflicts\n\n")
	m.printf("Evidence tiers disagree on the version of these components; deployed may differ from declared.\n")
	for _, c := range cs {
		m.printf("\n- **%s:** %s\n", orUnknown(escape(c.GetComponentKey())), escapeJoin(c.GetVersions()))
		m.evidence(c.GetEvidence())
	}
}

func (m *markdown) checked(ls []*touchstonev1.CheckedLocation) {
	m.printf("\n## Locations checked\n\n")
	if len(ls) == 0 {
		m.printf("No locations were recorded.\n")
		return
	}
	m.printf("| URL | Reason | Result | Error |\n|---|---|---|---|\n")
	for _, l := range ls {
		m.printf("| %s | %s | %s | %s |\n", escape(l.GetUrl()), escape(l.GetReason()),
			enumLabel(l.GetResult().String(), "RESULT_"), escape(l.GetError()))
	}
}

func (m *markdown) sources(ss []*touchstonev1.SourceStatus) {
	m.printf("\n## Sources\n\n")
	if len(ss) == 0 {
		m.printf("No sources were recorded.\n")
		return
	}
	m.printf("| Source | Status | Error |\n|---|---|---|\n")
	for _, s := range ss {
		st := "ok"
		if !s.GetOk() {
			st = "failed"
		}
		m.printf("| %s | %s | %s |\n", escape(s.GetSource()), st, escape(s.GetError()))
	}
}

// escape makes s safe to place inline in Markdown. HTML's & < > become
// entities so no tag survives; the characters that start Markdown
// constructs (emphasis, code spans, links, tables, strikethrough,
// backslash escapes) get a backslash; line breaks and other control
// characters, which could start a new block such as a heading, become a
// space. Callers never put an escaped string at the start of a line, so
// block-level markers (#, -, >, digits) need no escaping.
func escape(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '\\', '`', '*', '_', '[', ']', '|', '~':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			if unicode.IsControl(r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
				b.WriteByte(' ')
			} else {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}

func escapeJoin(ss []string) string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = escape(s)
	}
	return strings.Join(out, ", ")
}

func orUnknown(s string) string {
	if s == "" {
		return unknown
	}
	return s
}

func timestamp(ts *timestamppb.Timestamp) string {
	if ts == nil || !ts.IsValid() {
		return unknown
	}
	return ts.AsTime().UTC().Format(time.RFC3339)
}

func scanStatus(s touchstonev1.ScanStatus) string {
	switch s {
	case touchstonev1.ScanStatus_SCAN_STATUS_OK:
		return "ok"
	case touchstonev1.ScanStatus_SCAN_STATUS_TARGET_UNREACHABLE:
		return "target unreachable"
	default:
		return unknown
	}
}

// lookupStatus renders COMPLETE as "complete" and everything else as
// "lookup incomplete", with the reported status for the reader.
func lookupStatus(s touchstonev1.LookupStatus) string {
	switch s {
	case touchstonev1.LookupStatus_LOOKUP_STATUS_COMPLETE:
		return "complete"
	case touchstonev1.LookupStatus_LOOKUP_STATUS_PARTIAL:
		return "lookup incomplete (partial: at least one vulnerability source failed)"
	case touchstonev1.LookupStatus_LOOKUP_STATUS_FAILED:
		return "lookup incomplete (failed: no vulnerability source answered)"
	default:
		return "lookup incomplete (status unknown)"
	}
}

func vexStatus(v *touchstonev1.Vulnerability) string {
	switch v.GetVexStatus() {
	case touchstonev1.VexStatus_VEX_STATUS_AFFECTED:
		return "affected"
	case touchstonev1.VexStatus_VEX_STATUS_NOT_AFFECTED:
		return "not affected"
	case touchstonev1.VexStatus_VEX_STATUS_FIXED:
		return "fixed"
	case touchstonev1.VexStatus_VEX_STATUS_UNDER_INVESTIGATION:
		return "under investigation"
	default:
		return "n/a"
	}
}

// enumLabel turns an enum value name such as EVIDENCE_KIND_SBOM_PUBLISHED
// into "sbom published". Enum names come from the proto, not from vendors.
func enumLabel(name, prefix string) string {
	name = strings.TrimPrefix(name, prefix)
	return strings.ToLower(strings.ReplaceAll(name, "_", " "))
}

func score(f *float64) string {
	if f == nil {
		return "n/a"
	}
	return strconv.FormatFloat(*f, 'g', -1, 64)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}
