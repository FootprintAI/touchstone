package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	touchstonev1 "github.com/FootprintAI/touchstone/gen/go/touchstone/v1"
	"github.com/FootprintAI/touchstone/internal/fetch"
	"github.com/FootprintAI/touchstone/internal/service"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

var update = flag.Bool("update", false, "rewrite testdata/report.golden.json")

var (
	schemaPath = filepath.Join("..", "..", "schema", "scan-report.v1.json")
	goldenPath = filepath.Join("..", "..", "testdata", "report.golden.json")
)

func fixedStub(fetch.Options) touchstonev1.ScanServiceServer {
	return &service.Stub{Now: func() time.Time { return time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC) }}
}

func TestScanAllowPrivateFlag(t *testing.T) {
	for _, tt := range []struct {
		args []string
		want bool
	}{
		{[]string{"scan", "http://127.0.0.1:8080"}, false},
		{[]string{"scan", "--allow-private", "http://127.0.0.1:8080"}, true},
	} {
		var got *fetch.Options
		newSvc := func(o fetch.Options) touchstonev1.ScanServiceServer {
			got = &o
			return fixedStub(o)
		}
		if err := run(context.Background(), tt.args, &bytes.Buffer{}, newSvc); err != nil {
			t.Fatalf("run(%q): %v", tt.args, err)
		}
		if got == nil || got.AllowPrivate != tt.want {
			t.Errorf("run(%q): fetch options %+v, want AllowPrivate=%v", tt.args, got, tt.want)
		}
	}
}

func TestScanPrintsReportValidAgainstSchema(t *testing.T) {
	var out bytes.Buffer
	if err := run(context.Background(), []string{"scan", "https://example.com"}, &out, fixedStub); err != nil {
		t.Fatalf("run: %v", err)
	}

	c := jsonschema.NewCompiler()
	sch, err := c.Compile(schemaPath)
	if err != nil {
		t.Fatalf("compile %s: %v", schemaPath, err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(out.Bytes()))
	if err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out.String())
	}
	if err := sch.Validate(doc); err != nil {
		t.Fatalf("output does not validate against %s: %v\n%s", schemaPath, err, out.String())
	}
	if err := sch.Validate(map[string]any{"scanStatus": "NOT_A_STATUS"}); err == nil {
		t.Fatal("schema accepted an invalid report; validation is not effective")
	}

	var got touchstonev1.ScanReport
	if err := protojson.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("protojson.Unmarshal: %v", err)
	}
	if got.GetTargetUrl() != "https://example.com" {
		t.Errorf("target_url = %q, want https://example.com", got.GetTargetUrl())
	}
	if got.GetSchemaVersion() != "1" {
		t.Errorf("schema_version = %q, want 1", got.GetSchemaVersion())
	}

	// testdata/report.golden.json is also decoded by web/src/report.test.ts,
	// so drift between the Go and TS sides of the contract fails a test.
	if *update {
		var indented bytes.Buffer
		if err := json.Indent(&indented, out.Bytes(), "", "  "); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath, indented.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	golden, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden (run go test ./cmd/touchstone -update): %v", err)
	}
	var want touchstonev1.ScanReport
	if err := protojson.Unmarshal(golden, &want); err != nil {
		t.Fatalf("golden: %v", err)
	}
	if !proto.Equal(&got, &want) {
		t.Errorf("report differs from %s (run go test ./cmd/touchstone -update)\ngot:\n%s", goldenPath, out.String())
	}
}

func TestScanRejectsBadArgs(t *testing.T) {
	for _, args := range [][]string{
		nil, {"scan"}, {"serve", "https://example.com"}, {"scan", "ftp://example.com"}, {"scan", "example.com"},
		{"scan", "--allow-private"}, {"scan", "--no-such-flag", "https://example.com"}, {"scan", "https://a.example", "https://b.example"},
	} {
		if err := run(context.Background(), args, &bytes.Buffer{}, fixedStub); err == nil {
			t.Errorf("run(%q) = nil error, want error", args)
		}
	}
}
