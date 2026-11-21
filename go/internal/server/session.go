package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/jambonz/upload-recordings/go/internal/audio"
	"github.com/jambonz/upload-recordings/go/internal/creds"
	"github.com/jambonz/upload-recordings/go/internal/store"
	"github.com/jambonz/upload-recordings/go/internal/summary"
	"github.com/jambonz/upload-recordings/go/internal/wsproto"
)

const (
	// spoolBuffer is the audio held in memory per session before it is
	// written to the spool file: about one second of 8 kHz stereo.
	spoolBuffer = 32 * 1024
	// maxTextMessage bounds a metadata or session:summary message.
	maxTextMessage = 16 * 1024 * 1024

	// readInterval and readBuffer set how the socket is read; see
	// coalescingReader.
	readInterval = 200 * time.Millisecond
	readBuffer   = 16 * 1024

	lookupTimeout      = 15 * time.Second
	uploadTimeout      = 10 * time.Minute
	sessionJSONTimeout = 30 * time.Second
)

// session is one websocket connection, i.e. one call recording. All fields
// except timedOut belong to the goroutine running run.
type session struct {
	srv  *Server
	conn net.Conn
	br   *bufio.Reader
	log  *slog.Logger

	// audioStart approximates when audio capture began: connection time plus
	// one 20 ms packetization period.
	audioStart time.Time
	// timedOut is set by the metadata timer; from then on the session is
	// dead and everything the peer sends is ignored.
	timedOut atomic.Bool

	text         []byte // text message being assembled
	haveMetadata bool   // the first complete text message has been seen
	resolved     bool   // metadata has been looked up (successfully or not)
	pending      []byte // audio that arrived before resolved
	overflowed   bool

	info     store.CallInfo
	mp3      bool
	uploader store.Uploader
	summary  []byte // compact session:summary data, if one was sent

	spool    *os.File
	spoolW   *bufio.Writer
	pcmBytes int64
	spoolErr error
}

// coalescingReader reads the socket at most once per readInterval.
//
// A call delivers a 640-byte frame every 20 ms. Reading each one as it lands
// costs a goroutine wake-up and two read syscalls per frame, which measured
// about 75% more CPU than the C++ event loop. Nothing here needs a frame the
// instant it arrives, so the session lets the kernel's socket buffer collect
// a few and takes them in one read: ten times fewer wake-ups for the same
// bytes. The price is that a hang-up is noticed up to readInterval late.
type coalescingReader struct {
	conn   net.Conn
	last   time.Time
	behind bool // the last read filled the buffer: more is waiting
}

func (r *coalescingReader) Read(p []byte) (int, error) {
	if wait := readInterval - time.Since(r.last); wait > 0 && !r.behind {
		time.Sleep(wait)
	}
	n, err := r.conn.Read(p)
	r.last = time.Now()
	r.behind = n == len(p)
	return n, err
}

func newSession(srv *Server, conn net.Conn, hijacked *bufio.Reader) *session {
	// Anything the client sent right behind its handshake is already in the
	// HTTP server's reader; carry it over.
	early, _ := hijacked.Peek(hijacked.Buffered())
	br := bufio.NewReaderSize(io.MultiReader(bytes.NewReader(append([]byte(nil), early...)),
		&coalescingReader{conn: conn}), readBuffer)
	return &session{
		srv:        srv,
		conn:       conn,
		br:         br,
		log:        srv.log.With("session", srv.nextID.Add(1)),
		audioStart: time.Now().Add(20 * time.Millisecond),
	}
}

func (s *session) run() {
	s.log.Info("session created", "active_sessions", s.srv.sessionCreated())

	timer := time.AfterFunc(s.srv.cfg.MetadataTimeout, func() {
		s.timedOut.Store(true)
		s.log.Warn("No metadata received within timeout, destroying session",
			"active_sessions", s.srv.sessionDestroyed())
	})
	err := s.readLoop(timer)
	timer.Stop()
	s.conn.Close()
	s.srv.untrack(s.conn)

	if s.timedOut.Load() {
		return // already written off and counted as destroyed
	}
	if err != nil && !errors.Is(err, io.EOF) {
		s.log.Info("connection closed", "reason", err)
	} else {
		s.log.Info("connection closed")
	}
	s.finalize()
	s.log.Info("session destroyed", "active_sessions", s.srv.sessionDestroyed())
}

// readLoop consumes frames until the peer closes or the connection fails.
func (s *session) readLoop(timer *time.Timer) error {
	var msgOp byte // opcode of the data message in progress; 0 if none
	var ctl [125]byte
	for {
		h, err := wsproto.ReadHeader(s.br)
		if err != nil {
			return err
		}
		switch h.OpCode {
		case wsproto.OpClose, wsproto.OpPing, wsproto.OpPong:
			p := ctl[:0]
			if err := wsproto.ReadPayload(s.br, h, func(b []byte) error { p = append(p, b...); return nil }); err != nil {
				return err
			}
			switch h.OpCode {
			case wsproto.OpClose:
				if len(p) > 2 {
					p = p[:2] // echo the status code only
				}
				wsproto.WriteControl(s.conn, wsproto.OpClose, p)
				return nil
			case wsproto.OpPing:
				if err := wsproto.WriteControl(s.conn, wsproto.OpPong, p); err != nil {
					return err
				}
			}
			continue
		case wsproto.OpText, wsproto.OpBinary:
			msgOp = h.OpCode
		case wsproto.OpContinuation:
			if msgOp == 0 {
				return wsproto.ErrProtocol
			}
		default:
			return wsproto.ErrProtocol
		}

		switch {
		case s.timedOut.Load():
			err = wsproto.ReadPayload(s.br, h, nil)
		case msgOp == wsproto.OpBinary:
			err = wsproto.ReadPayload(s.br, h, s.audio)
		default:
			if err = wsproto.ReadPayload(s.br, h, s.appendText); err == nil {
				s.textReceived(timer)
			}
		}
		if err != nil {
			return err
		}
		if h.Fin {
			msgOp = 0
		}
	}
}

// audio receives a piece of a binary frame. This is the hot path: p aliases
// the connection's read buffer and is copied exactly once, into the spool
// writer.
func (s *session) audio(p []byte) error {
	switch {
	case s.spoolW != nil:
		if s.spoolErr != nil {
			return nil
		}
		if _, err := s.spoolW.Write(p); err != nil {
			s.spoolErr = err
			s.log.Error("Error writing to temporary file", "file", s.spool.Name(), "err", err)
			return nil
		}
		s.pcmBytes += int64(len(p))
	case s.resolved:
		// Metadata could not be resolved to a bucket; there is nowhere to
		// put this recording.
	case len(s.pending)+len(p) > s.srv.cfg.MaxPendingAudio:
		if !s.overflowed {
			s.overflowed = true
			s.log.Error("Buffer overflow: dropping audio received before metadata", "buffered", len(s.pending))
		}
	default:
		s.pending = append(s.pending, p...)
	}
	return nil
}

func (s *session) appendText(p []byte) error {
	if len(s.text)+len(p) > maxTextMessage {
		return fmt.Errorf("text message exceeds %d bytes", maxTextMessage)
	}
	s.text = append(s.text, p...)
	return nil
}

// textReceived runs after each text frame. Like the C++ service it does not
// rely on websocket message boundaries: text accumulates until it parses as
// JSON.
func (s *session) textReceived(timer *time.Timer) {
	if !json.Valid(s.text) {
		return
	}
	msg := s.text
	s.text = nil

	if !s.haveMetadata {
		s.haveMetadata = true
		if !timer.Stop() {
			return // the metadata timeout won the race; the session is dead
		}
		s.resolve(msg)
		return
	}

	var m map[string]json.RawMessage
	json.Unmarshal(msg, &m)
	switch {
	case jsonString(m["type"]) == "session:summary" && m["data"] != nil:
		var compact bytes.Buffer
		if json.Compact(&compact, m["data"]) == nil {
			s.summary = compact.Bytes()
			s.log.Info("Received session:summary", "bytes", len(s.summary))
		}
	case jsonString(m["event"]) == "dtmf":
		// The digit itself is deliberately not logged.
		var duration float64
		json.Unmarshal(m["duration"], &duration)
		s.log.Info("Unexpected text frame after metadata: dtmf event", "duration", duration)
	default:
		s.log.Info("Unexpected text frame after metadata", "frame", string(msg))
	}
}

func jsonString(raw json.RawMessage) string {
	var v string
	if raw == nil || json.Unmarshal(raw, &v) != nil {
		return ""
	}
	return v
}

// resolve turns the metadata message into an uploader and a spool file. It
// runs on the session's goroutine, so the connection is simply not read
// while the account is looked up; audio sent meanwhile waits in the socket
// buffer.
func (s *session) resolve(metadata []byte) {
	defer func() {
		s.resolved = true
		s.pending = nil
	}()

	var m map[string]json.RawMessage
	json.Unmarshal(metadata, &m)
	accountSid := jsonString(m["accountSid"])
	var rate float64
	json.Unmarshal(m["sampleRate"], &rate)
	s.info = store.CallInfo{
		// AccountSid is left empty: the C++ service never copies it into the
		// object metadata, so Account-Sid is stored blank. Kept identical
		// here; see BENCHMARKS.md ("Behaviour found").
		CallSid:                 jsonString(m["callSid"]),
		Direction:               jsonString(m["direction"]),
		From:                    jsonString(m["from"]),
		To:                      jsonString(m["to"]),
		ApplicationSid:          jsonString(m["applicationSid"]),
		OriginatingSipIP:        jsonString(m["originatingSipIp"]),
		OriginatingSipTrunkName: jsonString(m["fsSipAddress"]),
		SampleRate:              int(rate),
	}
	s.log = s.log.With("account_sid", accountSid, "call_sid", s.info.CallSid)
	s.log.Info("Received metadata")

	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	account, err := s.srv.cfg.Accounts.Lookup(ctx, accountSid)
	cancel()
	if err != nil {
		s.log.Error("Failed to fetch record credentials", "err", err)
		return
	}
	plain, err := creds.Decrypt(s.srv.cfg.EncryptionSecret, account.BucketCredential)
	if err != nil {
		s.log.Error("Failed to decrypt record credentials", "err", err)
		return
	}
	bucket, err := creds.ParseBucket(plain)
	if err != nil {
		s.log.Error("Failed to parse record credentials", "err", err)
		return
	}
	uploader, err := s.srv.cfg.Uploads.For(bucket)
	if err != nil {
		s.log.Warn("Failed to create storage uploader", "err", err)
		return
	}
	s.mp3 = account.RecordFormat == "mp3"
	if s.mp3 && !audio.MP3Supported {
		s.log.Error("Account records MP3 but this binary was built without LAME; recording dropped")
		return
	}
	if account.EvalCredential != "" {
		s.log.Warn("Account has a call-evaluation credential; that integration is not ported to this build and is skipped")
	}

	spool, err := os.CreateTemp(s.srv.cfg.TmpDir, "upload-*.tmp")
	if err != nil {
		s.log.Error("Failed to create temporary file", "err", err)
		return
	}
	w := bufio.NewWriterSize(spool, spoolBuffer)
	if !s.mp3 {
		// Reserve room for the WAV header; it is filled in at the end, when
		// the length is known, so the spool file is the object to upload.
		w.Write(make([]byte, audio.WAVHeaderLen))
	}
	w.Write(s.pending)
	s.pcmBytes = int64(len(s.pending))
	s.spool, s.spoolW, s.uploader = spool, w, uploader
	s.log.Info("Recording", "vendor", bucket.Vendor, "format", account.RecordFormat, "spool", spool.Name())
}

// finalize runs once the connection is gone: it encodes (MP3) or completes
// (WAV) the spooled audio, uploads it, then uploads session.json if a
// summary was received.
func (s *session) finalize() {
	if s.uploader == nil {
		s.log.Warn("connection closed but no storage uploader; nothing to upload")
		return
	}
	defer os.Remove(s.spool.Name())
	defer s.spool.Close()

	if err := s.spoolW.Flush(); err != nil && s.spoolErr == nil {
		s.spoolErr = err
	}
	s.spoolW = nil
	if s.spoolErr != nil {
		s.log.Error("Upload failed: recording could not be spooled", "err", s.spoolErr)
		return
	}

	object, size, ext := s.spool, audio.WAVHeaderLen+s.pcmBytes, "wav"
	if s.mp3 {
		encoded, n, err := s.encodeMP3()
		if err != nil {
			s.log.Error("MP3 encoding failed", "err", err)
			return
		}
		defer os.Remove(encoded.Name())
		defer encoded.Close()
		object, size, ext = encoded, n, "mp3"
	} else {
		header := audio.WAVHeader(uint32(s.pcmBytes))
		if _, err := s.spool.WriteAt(header[:], 0); err != nil {
			s.log.Error("Failed to write WAV header", "err", err)
			return
		}
	}

	now := time.Now()
	prefix := fmt.Sprintf("%d/%02d/%02d/", now.Year(), int(now.Month()), now.Day())
	key := prefix + s.info.CallSid + "." + ext

	ctx, cancel := context.WithTimeout(context.Background(), uploadTimeout)
	err := s.uploader.UploadRecording(ctx, key, object, size, s.info)
	cancel()
	if err != nil {
		s.log.Error("Failed to upload file", "key", key, "err", err)
		return
	}
	s.log.Info("File uploaded successfully", "key", key, "bytes", size, "took", time.Since(now).Round(time.Millisecond))

	if len(s.summary) > 0 {
		s.uploadSummary(prefix+s.info.CallSid+"/session.json", key)
	}
}

// encodeMP3 encodes the spooled PCM into a second temporary file. Encoding
// is the only CPU-heavy work in the service, so it is the only work that
// queues for a slot; reading audio from live calls never waits behind it.
func (s *session) encodeMP3() (*os.File, int64, error) {
	s.srv.encodeSlots <- struct{}{}
	defer func() { <-s.srv.encodeSlots }()

	if _, err := s.spool.Seek(0, io.SeekStart); err != nil {
		return nil, 0, err
	}
	out, err := os.CreateTemp(s.srv.cfg.TmpDir, "mp3file-*")
	if err != nil {
		return nil, 0, err
	}
	fail := func(err error) (*os.File, int64, error) {
		out.Close()
		os.Remove(out.Name())
		return nil, 0, err
	}
	start := time.Now()
	w := bufio.NewWriterSize(out, 64*1024)
	if _, err := audio.EncodeMP3(w, s.spool, s.info.SampleRate); err != nil {
		return fail(err)
	}
	if err := w.Flush(); err != nil {
		return fail(err)
	}
	size, err := out.Seek(0, io.SeekCurrent)
	if err != nil {
		return fail(err)
	}
	s.log.Info("Encoded PCM to MP3", "pcm_bytes", s.pcmBytes, "mp3_bytes", size,
		"took", time.Since(start).Round(time.Millisecond))
	return out, size, nil
}

func (s *session) uploadSummary(key, recordingKey string) {
	body, err := summary.Stamp(s.summary, recordingKey, s.audioStart)
	if err != nil {
		s.log.Error("Failed to stamp session summary", "err", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), sessionJSONTimeout)
	defer cancel()
	if err := s.uploader.UploadSessionJSON(ctx, key, body); err != nil {
		s.log.Error("Failed to upload session.json", "key", key, "err", err)
		return
	}
	s.log.Info("session.json uploaded successfully", "key", key)
}
