package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/FootprintAI/touchstone/internal/server"
	"github.com/FootprintAI/touchstone/internal/service"
)

const (
	serveUsage = "usage: touchstone serve [--addr host:port]"
	// defaultAddr is local-only on purpose: serve has no auth (design D3).
	defaultAddr = "127.0.0.1:8080"
)

// serve runs the web page and the ScanService HTTP API until interrupted.
// It has no --allow-private: the server never fetches private addresses.
func serve(ctx context.Context, args []string, static fs.FS) error {
	addr, err := parseServeArgs(args)
	if err != nil {
		return err
	}
	svc := &service.Stub{}
	handler, err := server.New(ctx, svc, static)
	if err != nil {
		return err
	}
	srv := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 10 * time.Second}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	fmt.Fprintf(os.Stderr, "touchstone: serving on http://%s\n", addr)

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	}
}

// parseServeArgs returns the listen address: --addr, else TOUCHSTONE_ADDR,
// else 127.0.0.1:8080.
func parseServeArgs(args []string) (string, error) {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addr := fs.String("addr", envOr("TOUCHSTONE_ADDR", defaultAddr), "listen address (env TOUCHSTONE_ADDR)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return "", errors.New(serveUsage)
	}
	return *addr, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
