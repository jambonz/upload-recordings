// Package server is the recording server: it accepts websocket connections
// from feature-server/mediajam, spools each call's audio to disk and, when
// the call ends, encodes and uploads it.
//
// Concurrency model: net/http runs one accept loop and starts a goroutine per
// connection. That goroutine is the session: it reads frames, writes audio to
// the session's spool file and, once the peer hangs up, finalizes the
// recording. Sessions share nothing on the audio path, so there is no lock
// there and the Go scheduler spreads them across cores. The only shared
// state is touched once per session (the registry, the DB pool, the storage
// client cache) or is a deliberate limit (encodeSlots).
package server

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jambonz/upload-recordings/go/internal/creds"
	"github.com/jambonz/upload-recordings/go/internal/db"
	"github.com/jambonz/upload-recordings/go/internal/metrics"
	"github.com/jambonz/upload-recordings/go/internal/store"
	"github.com/jambonz/upload-recordings/go/internal/wsproto"
)

// Subprotocol is the websocket subprotocol clients must offer.
const Subprotocol = "audio.jambonz.org"

// AccountLookup is the database dependency (satisfied by *db.DB).
type AccountLookup interface {
	Lookup(ctx context.Context, accountSid string) (db.Account, error)
}

// UploaderFactory is the storage dependency (satisfied by *store.Factory).
type UploaderFactory interface {
	For(b creds.Bucket) (store.Uploader, error)
}

// Config is everything a Server needs.
type Config struct {
	Log      *slog.Logger
	Accounts AccountLookup
	Uploads  UploaderFactory
	Statsd   *metrics.Statsd // may be nil

	EncryptionSecret string
	BasicAuthUser    string
	BasicAuthPass    string

	// TmpDir holds one spool file per live session.
	TmpDir string
	// MetadataTimeout is how long a new connection may stay silent before it
	// is written off.
	MetadataTimeout time.Duration
	// EncodeSlots bounds concurrent MP3 encodes, the only CPU-heavy work.
	EncodeSlots int
	// MaxPendingAudio bounds the audio held in memory while a session's
	// metadata has not arrived or is still being resolved.
	MaxPendingAudio int
}

// Server is the recording server.
type Server struct {
	cfg         Config
	log         *slog.Logger
	encodeSlots chan struct{}

	nextID atomic.Uint64
	active atomic.Int64 // sessions, as reported to statsd/CloudWatch

	mu       sync.Mutex // guards conns and closing; taken twice per session
	conns    map[net.Conn]struct{}
	closing  bool
	sessions sync.WaitGroup
	httpSrv  *http.Server
}

// New creates a server and its spool directory.
func New(cfg Config) (*Server, error) {
	if cfg.EncodeSlots < 1 {
		cfg.EncodeSlots = 1
	}
	if err := os.MkdirAll(cfg.TmpDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating spool directory: %w", err)
	}
	s := &Server{
		cfg:         cfg,
		log:         cfg.Log,
		encodeSlots: make(chan struct{}, cfg.EncodeSlots),
		conns:       make(map[net.Conn]struct{}),
	}
	s.httpSrv = &http.Server{Handler: s, ReadHeaderTimeout: 10 * time.Second}
	s.cfg.Statsd.Gauge(metrics.SessionsGauge, 0)
	return s, nil
}

// ActiveSessions is the number of sessions that exist right now, including
// those whose call has ended and whose recording is still being uploaded.
func (s *Server) ActiveSessions() int64 { return s.active.Load() }

// Serve accepts connections on l until Shutdown is called.
func (s *Server) Serve(l net.Listener) error {
	err := s.httpSrv.Serve(l)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown stops accepting, hangs up every live connection and waits until
// every session has finished uploading (or ctx expires). Recordings in
// flight are finalized, not discarded.
func (s *Server) Shutdown(ctx context.Context) error {
	s.httpSrv.Close()
	s.mu.Lock()
	s.closing = true
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()

	done := make(chan struct{})
	go func() { s.sessions.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !wsproto.IsUpgrade(r) {
		// Health check: any path beginning with /health.
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/health") {
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Length", "2")
			w.Write([]byte("OK"))
			return
		}
		http.NotFound(w, r)
		return
	}
	if !wsproto.OffersProtocol(r, Subprotocol) {
		http.Error(w, "unsupported websocket subprotocol", http.StatusBadRequest)
		return
	}
	if !s.authorized(r) {
		s.log.Warn("Unauthorized access attempt", "remote", r.RemoteAddr)
		w.Header().Set("WWW-Authenticate", `Basic realm="jambonz"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	conn, br, err := wsproto.Accept(w, r, Subprotocol)
	if err != nil {
		return
	}
	if !s.track(conn) {
		conn.Close()
		return
	}
	defer s.sessions.Done()
	newSession(s, conn, br).run()
}

// authorized checks HTTP Basic credentials. With no credentials configured
// every connection is refused, as in the C++ service.
func (s *Server) authorized(r *http.Request) bool {
	if s.cfg.BasicAuthUser == "" || s.cfg.BasicAuthPass == "" {
		return false
	}
	const prefix = "Basic "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return false
	}
	got, err := base64.StdEncoding.DecodeString(h[len(prefix):])
	if err != nil {
		return false
	}
	want := s.cfg.BasicAuthUser + ":" + s.cfg.BasicAuthPass
	return subtle.ConstantTimeCompare(got, []byte(want)) == 1
}

func (s *Server) track(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return false
	}
	s.conns[c] = struct{}{}
	s.sessions.Add(1)
	return true
}

func (s *Server) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

func (s *Server) sessionCreated() int64 {
	n := s.active.Add(1)
	s.cfg.Statsd.Gauge(metrics.SessionsGauge, float64(n))
	return n
}

func (s *Server) sessionDestroyed() int64 {
	n := s.active.Add(-1)
	s.cfg.Statsd.Gauge(metrics.SessionsGauge, float64(n))
	return n
}
