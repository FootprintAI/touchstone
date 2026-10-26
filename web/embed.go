// Package web embeds the static export of the Next.js page (web/out, built
// with `npm run build`). Only the placeholder .gitkeep is committed, so the
// Go build works before the page has been built; the page is then a 404.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:out
var embedded embed.FS

// Page returns the exported page rooted at its index.html.
func Page() fs.FS {
	sub, err := fs.Sub(embedded, "out")
	if err != nil {
		panic(err) // "out" is always embedded
	}
	return sub
}
