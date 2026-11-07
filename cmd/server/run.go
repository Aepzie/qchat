package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/craguS/qchat/internal/server"
	"github.com/craguS/qchat/internal/transport"
)

// cmdRun starts the server from a configuration file. It stops gracefully
// on SIGINT or SIGTERM or, when running as a Windows service, on a Stop or
// Shutdown request from the service manager.
func cmdRun(args []string, stderr io.Writer) error {
	fset := newFlagSet("run", "--config FILE", stderr)
	configPath := fset.String("config", "", "path of server.toml (required)")
	if err := parseFlags(fset, args); err != nil {
		return err
	}
	if *configPath == "" {
		return usagef(fset, "--config is required")
	}

	serve := func(ctx context.Context) error { return serveConfig(ctx, *configPath, stderr) }
	if handled, err := runAsService(serve); handled {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serveConfig(ctx, *configPath, stderr)
}

// serveConfig loads the configuration and identity and serves until ctx is
// cancelled. Logs are written as text to logOutput.
func serveConfig(ctx context.Context, configPath string, logOutput io.Writer) error {
	cfg, err := server.LoadConfig(configPath)
	if err != nil {
		return err
	}
	cert, err := transport.LoadServerCertificate(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return err
	}
	pin, err := transport.FingerprintOfTLS(cert)
	if err != nil {
		return err
	}
	level, err := cfg.Log.SlogLevel()
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewTextHandler(logOutput, &slog.HandlerOptions{Level: level}))
	srv, err := server.New(cfg, cert, logger)
	if err != nil {
		return err
	}
	logger.Info("server identity", "version", version, "fingerprint", pin.String())
	return srv.ListenAndServe(ctx)
}
