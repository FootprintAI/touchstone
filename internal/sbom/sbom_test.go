package sbom

import (
	"errors"
	"testing"
)

func TestParse(t *testing.T) {
	for _, tt := range []struct {
		name string
		doc  string
		want Format
		got  []Component
	}{
		{
			name: "cyclonedx with nested component",
			doc: `{"bomFormat":"CycloneDX","components":[
				{"name":"jquery","version":"3.7.1","purl":"pkg:npm/jquery@3.7.1","components":[{"name":"inner","version":"1"}]}]}`,
			want: CycloneDX,
			got: []Component{
				{Name: "jquery", Version: "3.7.1", Purl: "pkg:npm/jquery@3.7.1"},
				{Name: "inner", Version: "1"},
			},
		},
		{
			name: "spdx purl and cpe refs",
			doc: `{"spdxVersion":"SPDX-2.3","packages":[{"name":"openssl","versionInfo":"3.0.1","externalRefs":[
				{"referenceType":"purl","referenceLocator":"pkg:generic/openssl@3.0.1"},
				{"referenceType":"cpe23Type","referenceLocator":"cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*"}]}]}`,
			want: SPDX,
			got: []Component{{Name: "openssl", Version: "3.0.1", Purl: "pkg:generic/openssl@3.0.1",
				CPE: "cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*"}},
		},
		{
			name: "openvex products by purl",
			doc: `{"@context":"https://openvex.dev/ns/v0.2.0","statements":[
				{"vulnerability":{"name":"CVE-2024-1"},"products":[{"@id":"pkg:npm/%40scope/lib@1.0.0"}]}]}`,
			want: OpenVEX,
			got:  []Component{{Name: "lib", Version: "1.0.0", Purl: "pkg:npm/%40scope/lib@1.0.0"}},
		},
		{
			name: "csaf vex product tree",
			doc: `{"document":{"category":"csaf_vex"},"product_tree":{"branches":[{"branches":[
				{"product":{"name":"Foo 1.2 on Linux","product_id":"P1","product_identification_helper":{"purl":"pkg:maven/org.foo/foo@1.2"}}}]}]}}`,
			want: CSAFVEX,
			got:  []Component{{Name: "foo", Version: "1.2", Purl: "pkg:maven/org.foo/foo@1.2"}},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := Parse([]byte(tt.doc))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if doc.Format != tt.want {
				t.Errorf("format = %s, want %s", doc.Format, tt.want)
			}
			if len(doc.Components) != len(tt.got) {
				t.Fatalf("components = %+v, want %+v", doc.Components, tt.got)
			}
			for i, c := range tt.got {
				if doc.Components[i] != c {
					t.Errorf("component %d = %+v, want %+v", i, doc.Components[i], c)
				}
			}
		})
	}
}

func TestParseRejects(t *testing.T) {
	if _, err := Parse([]byte(`{"document":{"category":"csaf_security_advisory"}}`)); !errors.Is(err, ErrUnknownFormat) {
		t.Errorf("non-VEX CSAF: err = %v, want ErrUnknownFormat", err)
	}
	if _, err := Parse([]byte(`{`)); err == nil || errors.Is(err, ErrUnknownFormat) {
		t.Errorf("malformed JSON: err = %v, want a decode error", err)
	}
}
