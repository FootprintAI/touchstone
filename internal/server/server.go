// Package server is the HTTP face of touchstone serve. The ScanService is
// exposed under /v1/ through grpc-gateway, which calls the service in
// process; every other path serves the embedded static web page.
package server

import (
	"context"
	"io/fs"
	"net/http"

	touchstonev1 "github.com/FootprintAI/touchstone/gen/go/touchstone/v1"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
)

// maxRequestBytes caps a request body. A ScanRequest carrying only a URL is
// a few hundred bytes; sbom_document uploads (D1) will need a larger cap.
const maxRequestBytes = 1 << 20

// New returns the handler for touchstone serve: svc under /v1/ and static
// at every other path.
func New(ctx context.Context, svc touchstonev1.ScanServiceServer, static fs.FS) (http.Handler, error) {
	gw := runtime.NewServeMux()
	if err := touchstonev1.RegisterScanServiceHandlerServer(ctx, gw, svc); err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("/v1/", http.MaxBytesHandler(gw, maxRequestBytes))
	mux.Handle("/", http.FileServerFS(static))
	return mux, nil
}
