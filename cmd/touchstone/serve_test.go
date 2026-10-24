package main

import "testing"

func TestParseServeArgsAddress(t *testing.T) {
	t.Setenv("TOUCHSTONE_ADDR", "")
	for _, tt := range []struct {
		name string
		env  string
		args []string
		want string
	}{
		{"default is loopback", "", nil, "127.0.0.1:8080"},
		{"env overrides default", "0.0.0.0:9000", nil, "0.0.0.0:9000"},
		{"flag overrides env", "0.0.0.0:9000", []string{"--addr", "127.0.0.1:7000"}, "127.0.0.1:7000"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TOUCHSTONE_ADDR", tt.env)
			got, err := parseServeArgs(tt.args)
			if err != nil || got != tt.want {
				t.Fatalf("parseServeArgs(%q) = %q, %v; want %q", tt.args, got, err, tt.want)
			}
		})
	}
}

func TestParseServeArgsRejectsPositionalAndUnknownFlags(t *testing.T) {
	for _, args := range [][]string{
		{"https://example.com"},
		{"--allow-private"},
		{"--addr"},
	} {
		if _, err := parseServeArgs(args); err == nil {
			t.Errorf("parseServeArgs(%q) = nil error, want error", args)
		}
	}
}
