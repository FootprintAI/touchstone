package sbom

import (
	"errors"
	"reflect"
	"testing"
)

const cycloneDX = `{
  "bomFormat": "CycloneDX", "specVersion": "1.6",
  "components": [
    {"name": "jquery", "version": "3.7.1", "purl": "pkg:npm/jquery@3.7.1",
     "components": [{"name": "sizzle", "version": "2.3.10", "purl": "pkg:npm/sizzle@2.3.10"}]},
    {"group": "org.apache.logging.log4j", "name": "log4j-core", "version": "2.17.1"}
  ]
}`

const spdx = `{
  "spdxVersion": "SPDX-2.3",
  "packages": [
    {"name": "lodash", "versionInfo": "4.17.21",
     "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/lodash@4.17.21"}]},
    {"name": "openssl", "versionInfo": "3.0.13",
     "externalRefs": [{"referenceCategory": "SECURITY", "referenceType": "cpe23Type", "referenceLocator": "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*"}]}
  ]
}`

const openVEX = `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "statements": [
    {"vulnerability": {"name": "CVE-2020-11022"}, "status": "not_affected",
     "products": [{"@id": "pkg:npm/jquery@1.12.4"}, {"@id": "pkg:npm/jquery@1.12.4"}]}
  ]
}`

// csafVEX is a minimal CSAF 2.0 VEX document: one product under
// vendor/product_name/product_version branches, one full product name.
const csafVEX = `{
  "document": {"category": "csaf_vex", "csaf_version": "2.0", "title": "Example VEX"},
  "product_tree": {
    "branches": [{"category": "vendor", "name": "Example", "branches": [
      {"category": "product_name", "name": "nginx", "branches": [
        {"category": "product_version", "name": "1.25.3",
         "product": {"product_id": "P1", "name": "Example nginx 1.25.3",
           "product_identification_helper": {"cpe": "cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*"}}}
      ]}
    ]}],
    "full_product_names": [
      {"product_id": "P2", "name": "jquery 3.7.1", "product_identification_helper": {"purl": "pkg:npm/jquery@3.7.1"}}
    ]
  },
  "vulnerabilities": [{"cve": "CVE-2023-44487", "product_status": {"known_not_affected": ["P1"]}}]
}`

func TestParse(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want Document
	}{
		{"CycloneDX", cycloneDX, Document{Format: FormatCycloneDX, Components: []Component{
			{Name: "jquery", Version: "3.7.1", Purl: "pkg:npm/jquery@3.7.1"},
			{Name: "sizzle", Version: "2.3.10", Purl: "pkg:npm/sizzle@2.3.10"},
			{Name: "org.apache.logging.log4j/log4j-core", Version: "2.17.1"},
		}}},
		{"SPDX", spdx, Document{Format: FormatSPDX, Components: []Component{
			{Name: "lodash", Version: "4.17.21", Purl: "pkg:npm/lodash@4.17.21"},
			{Name: "openssl", Version: "3.0.13", CPE: "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*"},
		}}},
		{"OpenVEX", openVEX, Document{Format: FormatOpenVEX, VEX: true, Components: []Component{
			{Name: "jquery", Version: "1.12.4", Purl: "pkg:npm/jquery@1.12.4"},
		}, Statements: []Statement{{
			Vulnerability: "CVE-2020-11022", Status: VEXNotAffected,
			Products: []Component{
				{Name: "jquery", Version: "1.12.4", Purl: "pkg:npm/jquery@1.12.4"},
				{Name: "jquery", Version: "1.12.4", Purl: "pkg:npm/jquery@1.12.4"},
			},
		}}}},
		{"CSAF VEX", csafVEX, Document{Format: FormatCSAF, VEX: true, Components: []Component{
			{Name: "nginx", Version: "1.25.3", CPE: "cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*"},
			{Name: "jquery", Version: "3.7.1", Purl: "pkg:npm/jquery@3.7.1"},
		}, Statements: []Statement{{
			Vulnerability: "CVE-2023-44487", Status: VEXNotAffected,
			Products: []Component{{Name: "nginx", Version: "1.25.3", CPE: "cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*"}},
		}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse([]byte(tt.in))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if !reflect.DeepEqual(*got, tt.want) {
				t.Errorf("Parse =\n%+v\nwant\n%+v", *got, tt.want)
			}
		})
	}
}

func TestParseCSAFAdvisoryIsNotVEX(t *testing.T) {
	doc, err := ParseCSAF([]byte(`{"document": {"category": "csaf_security_advisory", "csaf_version": "2.0"}}`))
	if err != nil {
		t.Fatalf("ParseCSAF: %v", err)
	}
	if doc.VEX {
		t.Error("VEX = true for a security advisory")
	}
}

func TestParseRejects(t *testing.T) {
	for _, in := range []string{"", "not json", "{}", `{"bomFormat": "Other"}`, "<bom/>", `{"document": {}}`} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("Parse(%q) = nil error, want error", in)
		}
	}
	if _, err := Parse([]byte("<bom/>")); !errors.Is(err, ErrUnknownFormat) {
		t.Errorf("Parse(XML): err = %v, want ErrUnknownFormat", err)
	}
}

func TestPurlNameVersion(t *testing.T) {
	tests := []struct{ purl, name, version string }{
		{"pkg:npm/jquery@1.12.4", "jquery", "1.12.4"},
		{"pkg:npm/%40angular/core@17.0.0", "core", "17.0.0"},
		{"pkg:maven/org.apache/log4j-core@2.17.1?type=jar", "log4j-core", "2.17.1"},
		{"pkg:golang/golang.org/x/net", "net", ""},
	}
	for _, tt := range tests {
		name, version := purlNameVersion(tt.purl)
		if name != tt.name || version != tt.version {
			t.Errorf("purlNameVersion(%q) = %q, %q; want %q, %q", tt.purl, name, version, tt.name, tt.version)
		}
	}
}
