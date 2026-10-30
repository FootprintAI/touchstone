package discover

import "strings"

// SecurityTxt is the part of an RFC 9116 security.txt that discovery
// uses. Field names are matched case-insensitively and every occurrence
// of a field is kept, in file order.
type SecurityTxt struct {
	Contact []string
	Expires string
	// CSAF holds the values of every CSAF: field (CSAF 2.0, section
	// 7.1.8): URLs of provider-metadata.json documents.
	CSAF []string
}

// ParseSecurityTxt reads a security.txt. It is lenient, as a reader should
// be: comments, blank lines, CRLF line endings, unknown fields and an
// OpenPGP cleartext signature are all accepted, and a line that is not a
// field is skipped.
func ParseSecurityTxt(body []byte) *SecurityTxt {
	st := &SecurityTxt{}
	inSignature := false
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(line, "-----BEGIN PGP SIGNATURE-----"):
			inSignature = true
			continue
		case strings.HasPrefix(line, "-----END PGP SIGNATURE-----"):
			inSignature = false
			continue
		case inSignature, strings.HasPrefix(line, "-----BEGIN PGP SIGNED MESSAGE-----"):
			continue
		}
		// Dash-escaped lines of a cleartext-signed message (RFC 4880, 7.1).
		line = strings.TrimPrefix(line, "- ")
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "contact":
			st.Contact = append(st.Contact, value)
		case "expires":
			st.Expires = value
		case "csaf":
			st.CSAF = append(st.CSAF, value)
		}
	}
	return st
}
