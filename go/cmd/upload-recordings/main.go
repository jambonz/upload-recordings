// Command upload_recordings is the jambonz recording server: it receives
// call audio over websocket and uploads it to the account's bucket.
//
// It takes the same flags and environment as the C++ service it is a
// proposed replacement for, so the existing systemd unit works unchanged.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/jambonz/upload-recordings/go/internal/audio"
	"github.com/jambonz/upload-recordings/go/internal/db"
	"github.com/jambonz/upload-recordings/go/internal/metrics"
	"github.com/jambonz/upload-recordings/go/internal/server"
	"github.com/jambonz/upload-recordings/go/internal/store"
)

// version is stamped at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

func main() {
	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	port := fs.Int("port", 3017, "Server port")
	threads := fs.Int("threads", 0, "Cores to use (sets GOMAXPROCS; default: all available)")
	maxConns := fs.Int("aws-max-connections", 64, "Max concurrent upload connections per storage host")
	fs.Int("buffer-process-size", 512, "Accepted for compatibility; ignored (audio is spooled to disk as it arrives)")
	maxBuffer := fs.Int("max-buffer-size", 3, "Max audio in MB held per session before its metadata is resolved")
	showVersion := fs.Bool("version", false, "Show version")
	fs.BoolVar(showVersion, "v", false, "Show version")
	fs.Int("d", 0, "Accepted for compatibility; ignored (libwebsockets log level)")
	tls := fs.Bool("s", false, "Not supported: TLS with the test certificate")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s [OPTIONS]\nOptions:\n", os.Args[0])
		fs.PrintDefaults()
		fmt.Fprint(fs.Output(), "\nEnvironment Variables:\n"+
			"  LOG_LEVEL                      debug, info, warn or error (default info)\n"+
			"  ENCRYPTION_SECRET              Required for credential decryption\n"+
			"  BASIC_AUTH_USERNAME            WebSocket basic auth username\n"+
			"  BASIC_AUTH_PASSWORD            WebSocket basic auth password\n"+
			"  MYSQL_HOST, MYSQL_USER, MYSQL_DATABASE\n"+
			"  JAMBONES_MYSQL_PASSWORD        (falls back to MYSQL_PASSWORD)\n"+
			"  JAMBONZ_UPLOADER_TMP_FOLDER    Spool folder (default /tmp/uploads)\n"+
			"  JAMBONZ_METADATA_TIMEOUT_SECS  Seconds to wait for call metadata (default 3)\n"+
			"  S3_PATH_STYLE_SERVICES         Comma-separated endpoint substrings needing path-style S3\n"+
			"  JAMBONES_STATSD_PREFIX, STATS_HOST, STATS_PORT, STATS_PROTOCOL\n")
	}
	fs.Parse(os.Args[1:])

	if *showVersion {
		fmt.Println("jambonz recording server (ws) version", version)
		return
	}

	level := slog.LevelInfo
	switch os.Getenv("LOG_LEVEL") {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))

	secret := os.Getenv("ENCRYPTION_SECRET")
	if secret == "" {
		log.Error("ENCRYPTION_SECRET environment variable is not set")
		os.Exit(1)
	}
	if *tls {
		log.Error("-s (TLS) is not supported by this build")
		os.Exit(1)
	}
	if *threads > 0 {
		runtime.GOMAXPROCS(*threads)
	}
	cores := runtime.GOMAXPROCS(0)

	tmpDir := os.Getenv("JAMBONZ_UPLOADER_TMP_FOLDER")
	if tmpDir == "" {
		tmpDir = "/tmp/uploads"
	}
	metadataTimeout := 3 * time.Second
	if n, err := strconv.Atoi(os.Getenv("JAMBONZ_METADATA_TIMEOUT_SECS")); err == nil && n > 0 {
		metadataTimeout = time.Duration(n) * time.Second
	}

	log.Info("Configuration", "cores", cores, "max_upload_connections", *maxConns,
		"spool_dir", tmpDir, "port", *port, "mp3", audio.MP3Supported)
	if !audio.MP3Supported {
		log.Warn("Built with the nolame tag: recordings for accounts with record_format mp3 will be dropped")
	}

	// Probe the database before serving, so a wrong password or unreachable
	// host shows up in the log now rather than on the first call. Not fatal:
	// a database that is briefly down at boot must not crash-loop the unit.
	database := db.Open()
	defer database.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := database.Ping(ctx); err != nil {
		log.Error("MySQL: NOT reachable - recordings will fail until this is fixed", "err", err)
	} else {
		log.Info("MySQL: connected", "host", os.Getenv("MYSQL_HOST"), "database", os.Getenv("MYSQL_DATABASE"))
	}
	cancel()

	srv, err := server.New(server.Config{
		Log:              log,
		Accounts:         database,
		Uploads:          store.NewFactory(*maxConns),
		Statsd:           metrics.NewStatsd(log),
		EncryptionSecret: secret,
		BasicAuthUser:    os.Getenv("BASIC_AUTH_USERNAME"),
		BasicAuthPass:    os.Getenv("BASIC_AUTH_PASSWORD"),
		TmpDir:           tmpDir,
		MetadataTimeout:  metadataTimeout,
		EncodeSlots:      cores,
		MaxPendingAudio:  *maxBuffer * 1024 * 1024,
	})
	if err != nil {
		log.Error("startup failed", "err", err)
		os.Exit(1)
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Error("listen failed", "err", err)
		os.Exit(1)
	}

	bg, stopBackground := context.WithCancel(context.Background())
	go metrics.RunCloudWatch(bg, log, srv.ActiveSessions)

	served := make(chan error, 1)
	go func() { served <- srv.Serve(listener) }()
	log.Info(fmt.Sprintf("jambonz recording server (ws) version %s | Listening on http://localhost:%d", version, *port))

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-signals:
		log.Info("Shutting down server", "signal", sig.String(), "active_sessions", srv.ActiveSessions())
	case err := <-served:
		log.Error("server stopped", "err", err)
	}
	// Like the C++ service, finish every recording in flight before exiting.
	// Uploads have their own timeouts; systemd's stop timeout is the backstop.
	srv.Shutdown(context.Background())
	stopBackground()
	log.Info("Shutdown complete")
}
