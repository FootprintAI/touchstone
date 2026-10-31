package sbom

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func readFixture(t testing.TB, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseFixtures(t *testing.T) {
	jquery := Component{Name: "jquery", Version: "3.7.1", Purl: "pkg:npm/jquery@3.7.1"}
	lodash := Component{Name: "lodash", Version: "4.17.21", Purl: "pkg:npm/lodash@4.17.21"}
	log4jPurl := Component{Name: "log4j-core", Version: "2.17.1", Purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"}
	other := Component{Name: "other", Version: "1.0.0", Purl: "pkg:npm/other@1.0.0"}
	nginx := Component{Name: "nginx", Version: "1.25.3", CPE: "cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*"}

	tests := []struct {
		file string
		want Document
	}{
		{"cyclonedx-1.5.json", Document{Format: FormatCycloneDX, Components: []Component{
			lodash,
			{Name: "express", Version: "4.18.2", Purl: "pkg:npm/express@4.18.2"},
			{Name: "qs", Version: "6.11.0", Purl: "pkg:npm/qs@6.11.0"},
		}}},
		{"cyclonedx-vex-1.6.json", Document{Format: FormatCycloneDX, VEX: true,
			Components: []Component{
				jquery,
				{Name: "org.apache.logging.log4j/log4j-core", Version: "2.17.1"},
			},
			Statements: []Statement{
				{Vulnerability: "CVE-2020-11022", Aliases: []string{"GHSA-gxr4-xjj5-5px2"}, Status: VEXNotAffected,
					Justification: "code_not_reachable: the vulnerable API is never called", Products: []Component{jquery}},
				{Vulnerability: "CVE-2021-44228", Status: VEXFixed,
					Products: []Component{{Name: "org.apache.logging.log4j/log4j-core", Version: "2.17.1"}}},
				{Vulnerability: "CVE-2022-0001", Status: VEXAffected, Products: []Component{other}},
			}}},
		{"spdx-2.3.json", Document{Format: FormatSPDX, Components: []Component{
			lodash,
			{Name: "openssl", Version: "3.0.13", CPE: "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*"},
		}}},
		{"openvex.json", Document{Format: FormatOpenVEX, VEX: true,
			Components: []Component{jquery, log4jPurl, other},
			Statements: []Statement{
				{Vulnerability: "CVE-2020-11022", Aliases: []string{"GHSA-gxr4-xjj5-5px2"}, Status: VEXNotAffected,
					Justification: "vulnerable_code_not_in_execute_path: never called", Products: []Component{jquery}},
				{Vulnerability: "CVE-2021-44228", Status: VEXFixed, Products: []Component{log4jPurl}},
				{Vulnerability: "CVE-2022-0001", Status: VEXUnderInvestigation, Products: []Component{other}},
			}}},
		{"csaf-vex.json", Document{Format: FormatCSAF, VEX: true,
			Components: []Component{
				nginx,
				jquery,
				{Name: "lodash", Version: "4.17.20", Purl: "pkg:npm/lodash@4.17.20"},
			},
			Statements: []Statement{
				{Vulnerability: "CVE-2023-44487", Aliases: []string{"GHSA-qppj-fm5r-hxr3"}, Status: VEXNotAffected,
					Justification: "vulnerable_code_not_in_execute_path", Products: []Component{nginx}},
				{Vulnerability: "CVE-2023-44487", Aliases: []string{"GHSA-qppj-fm5r-hxr3"}, Status: VEXAffected,
					Products: []Component{{Name: "lodash", Version: "4.17.20", Purl: "pkg:npm/lodash@4.17.20"}}},
				{Vulnerability: "CVE-2020-11022", Status: VEXFixed, Products: []Component{jquery}},
			}}},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			got, err := Parse(readFixture(t, tt.file))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if !reflect.DeepEqual(*got, tt.want) {
				t.Errorf("Parse =\n%+v\nwant\n%+v", *got, tt.want)
			}
		})
	}
}

func TestParseMalformedIsTyped(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		format Format
	}{
		{"CycloneDX", `{"bomFormat": "CycloneDX", "components": "x"}`, FormatCycloneDX},
		{"SPDX", `{"spdxVersion": "SPDX-2.3", "packages": {}}`, FormatSPDX},
		{"OpenVEX", `{"@context": "https://openvex.dev/ns", "statements": "x"}`, FormatOpenVEX},
		{"CSAF", `{"document": {"category": "csaf_vex"}}`, FormatCSAF},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.in))
			var pe *ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("err = %v, want *ParseError", err)
			}
			if pe.Format != tt.format {
				t.Errorf("Format = %q, want %q", pe.Format, tt.format)
			}
		})
	}
}

func TestOpenVEXLegacyStringVulnerability(t *testing.T) {
	doc, err := Parse([]byte(`{"@context": "https://openvex.dev/ns", "statements": [
		{"vulnerability": "CVE-2020-1", "products": ["x"], "status": "fixed"}]}`))
	if err == nil {
		// products as bare strings are not valid OpenVEX; only the typed error matters.
		t.Fatalf("Parse = %+v, want error for string products", doc)
	}
	var pe *ParseError
	if !errors.As(err, &pe) {
		t.Errorf("err = %v, want *ParseError", err)
	}
	doc, err = Parse([]byte(`{"@context": "https://openvex.dev/ns", "statements": [
		{"vulnerability": "CVE-2020-1", "products": [{"@id": "pkg:npm/a@1"}], "status": "fixed"}]}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(doc.Statements) != 1 || doc.Statements[0].Vulnerability != "CVE-2020-1" {
		t.Errorf("Statements = %+v", doc.Statements)
	}
}
