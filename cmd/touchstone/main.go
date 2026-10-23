// Command touchstone scans a vendor URL and prints an evidence-graded
// ScanReport as protojson. In slice S0 the scan is served by the stub
// ScanService, so the report is canned.
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
	"github.com/FootprintAI/touchstone/internal/service"
	"google.golang.org/protobuf/encoding/protojson"
)

const usage = "usage: touchstone scan [--allow-private] <url>"

// newService builds the ScanService for one CLI invocation. The fetch
// options carry CLI-only settings such as --allow-private, which the
// server never accepts.
type newService func(fetch.Options) touchstonev1.ScanServiceServer

func main() {
	newSvc := func(fetch.Options) touchstonev1.ScanServiceServer { return &service.Stub{} }
	if err := run(context.Background(), os.Args[1:], os.Stdout, newSvc); err != nil {
		fmt.Fprintln(os.Stderr, "touchstone:", err)
		os.Exit(2)
	}
}

func run(ctx context.Context, args []string, out io.Writer, newSvc newService) error {
	if len(args) == 0 || args[0] != "scan" {
		return errors.New(usage)
	}
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	allowPrivate := fs.Bool("allow-private", false, "allow fetching loopback and private addresses (local fixtures only)")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 1 {
		return errors.New(usage)
	}
	svc := newSvc(fetch.Options{AllowPrivate: *allowPrivate, Version: service.ToolVersion})
	report, err := svc.Scan(ctx, &touchstonev1.ScanRequest{Url: fs.Arg(0)})
	if err != nil {
		return err
	}
	b, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(report)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(b))
	return err
}
