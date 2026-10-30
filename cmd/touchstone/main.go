// Command touchstone scans a vendor URL and prints an evidence-graded
// ScanReport as protojson (--format json, the default) or as Markdown
// (--format md), or serves the web page and POST /v1/scans (serve, slice
// S9). The scan fetches the page and its scripts passively and looks
// components up in OSV (by purl) and NVD (by CPE), enriched with KEV and
// EPSS.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	touchstonev1 "github.com/FootprintAI/touchstone/gen/go/touchstone/v1"
	"github.com/FootprintAI/touchstone/internal/fetch"
	"github.com/FootprintAI/touchstone/internal/report"
	"github.com/FootprintAI/touchstone/internal/service"
	"github.com/FootprintAI/touchstone/internal/vuln"
	"google.golang.org/protobuf/encoding/protojson"
)

const usage = "usage: touchstone scan [--allow-private] [--format json|md] <url>\n       touchstone serve [--addr host:port]"

// newService builds the ScanService for one CLI invocation. The fetch
// options carry CLI-only settings such as --allow-private, which the
// server never accepts.
type newService func(fetch.Options) touchstonev1.ScanServiceServer

func main() {
	newSvc := func(o fetch.Options) touchstonev1.ScanServiceServer {
		// NVD_API_KEY is optional; without it NVD lookups are capped.
		nvdKey := os.Getenv("NVD_API_KEY")
		return &service.Scanner{
			Fetch:  o,
			Vulns:  vuln.NewOSV(),
			CPE:    vuln.NewNVD(nvdKey),
			CPEMax: vuln.NVDMaxLookups(nvdKey),
			KEV:    vuln.NewKEV(),
			EPSS:   vuln.NewEPSS(),
		}
	}
	if err := run(context.Background(), os.Args[1:], os.Stdout, newSvc); err != nil {
		fmt.Fprintln(os.Stderr, "touchstone:", err)
		os.Exit(2)
	}
}

func run(ctx context.Context, args []string, out io.Writer, newSvc newService) error {
	if len(args) > 0 && args[0] == "serve" {
		return serve(ctx, args[1:], out, os.Stderr, newSvc)
	}
	if len(args) == 0 || args[0] != "scan" {
		return errors.New(usage)
	}
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	allowPrivate := fs.Bool("allow-private", false, "allow fetching loopback and private addresses (local fixtures only)")
	format := fs.String("format", "json", "output format: json (protojson) or md (Markdown)")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 1 {
		return errors.New(usage)
	}
	render, err := renderer(*format)
	if err != nil {
		return err
	}
	svc := newSvc(fetch.Options{AllowPrivate: *allowPrivate, Version: service.ToolVersion})
	rep, err := svc.Scan(ctx, &touchstonev1.ScanRequest{Url: fs.Arg(0)})
	if err != nil {
		return err
	}
	return render(out, rep)
}

// renderer picks the output format. Unknown formats are rejected before
// the scan runs, so a typo never costs a scan.
func renderer(format string) (func(io.Writer, *touchstonev1.ScanReport) error, error) {
	switch format {
	case "json":
		return writeJSON, nil
	case "md", "markdown":
		return report.WriteMarkdown, nil
	default:
		return nil, fmt.Errorf("unknown --format %q, want json or md\n%s", format, usage)
	}
}

func writeJSON(out io.Writer, rep *touchstonev1.ScanReport) error {
	b, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(rep)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(b))
	return err
}
