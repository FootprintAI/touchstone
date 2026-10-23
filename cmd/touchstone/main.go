// Command touchstone scans a vendor URL and prints an evidence-graded
// ScanReport as protojson. In slice S0 the scan is served by the stub
// ScanService, so the report is canned.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	touchstonev1 "github.com/FootprintAI/touchstone/gen/go/touchstone/v1"
	"github.com/FootprintAI/touchstone/internal/service"
	"google.golang.org/protobuf/encoding/protojson"
)

const usage = "usage: touchstone scan <url>"

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, &service.Stub{}); err != nil {
		fmt.Fprintln(os.Stderr, "touchstone:", err)
		os.Exit(2)
	}
}

func run(ctx context.Context, args []string, out io.Writer, svc touchstonev1.ScanServiceServer) error {
	if len(args) != 2 || args[0] != "scan" {
		return errors.New(usage)
	}
	report, err := svc.Scan(ctx, &touchstonev1.ScanRequest{Url: args[1]})
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
