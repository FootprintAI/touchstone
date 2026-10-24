// Package web embeds the Next.js static export that `touchstone serve`
// returns. `make web-build` writes the export to web/out; it is not
// committed. out/.gitkeep keeps the embed pattern valid on a fresh checkout.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:out
var out embed.FS

// Static returns the exported page with out/ stripped, so index.html and
// _next/ sit at the root.
func Static() (fs.FS, error) {
	return fs.Sub(out, "out")
}
