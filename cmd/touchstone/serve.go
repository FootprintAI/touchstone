package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"time"

	touchstonev1 "github.com/FootprintAI/touchstone/gen/go/touchstone/v1"
	"github.com/FootprintAI/touchstone/internal/fetch"
	"github.com/FootprintAI/touchstone/internal/service"
	"github.com/FootprintAI/touchstone/web"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	defaultAddr = "127.0.0.1:8080"

	// scanTimeout bounds one scan request end to end.
	scanTimeout = 180 * time.Second
)

// serve runs the embedded page and POST /v1/scans on one port. It has no
// --allow-private: the fetch options carry only the tool version, so the
// server always refuses loopback and private targets.
func serve(ctx context.Context, args []string, out io.Writer, newSvc newService) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	addr := flags.String("addr", envOr("TOUCHSTONE_ADDR", defaultAddr), "listen address (env TOUCHSTONE_ADDR)")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return errors.New(usage)
	}
	handler, err := newHandler(ctx, newSvc(fetch.Options{Version: service.ToolVersion}), web.Page())
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      scanTimeout + 10*time.Second,
	}
	fmt.Fprintf(out, "touchstone: listening on http://%s\n", ln.Addr())

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	}
}

// newHandler routes /v1/ to the ScanService through grpc-gateway and
// everything else to the static page.
func newHandler(ctx context.Context, svc touchstonev1.ScanServiceServer, page fs.FS) (http.Handler, error) {
	// Default protojson options, so the REST body has the same shape as the
	// CLI's JSON that the page decodes with the generated fromJson.
	gw := runtime.NewServeMux(runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.JSONPb{
		MarshalOptions:   protojson.MarshalOptions{},
		UnmarshalOptions: protojson.UnmarshalOptions{DiscardUnknown: true},
	}))
	if err := touchstonev1.RegisterScanServiceHandlerServer(ctx, gw, svc); err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("/v1/", withTimeout(gw, scanTimeout))
	mux.Handle("/", http.FileServerFS(page))
	return mux, nil
}

func withTimeout(next http.Handler, d time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), d)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
