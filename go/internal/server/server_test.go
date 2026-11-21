package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/jambonz/upload-recordings/go/internal/audio"
	"github.com/jambonz/upload-recordings/go/internal/benchutil"
	"github.com/jambonz/upload-recordings/go/internal/creds"
	"github.com/jambonz/upload-recordings/go/internal/db"
	"github.com/jambonz/upload-recordings/go/internal/store"
	"github.com/jambonz/upload-recordings/go/internal/wsproto"
)

const secret = "test-secret"

type accounts map[string]db.Account

func (a accounts) Lookup(_ context.Context, sid string) (db.Account, error) {
	acct, ok := a[sid]
	if !ok {
		return db.Account{}, errors.New("account not found")
	}
	return acct, nil
}

// bucket is an in-memory object store standing in for S3.
type bucket struct {
	mu      sync.Mutex
	objects map[string][]byte
	infos   map[string]store.CallInfo
	gate    chan struct{} // when set, uploads block until it is closed
	fail    bool
}

func (b *bucket) For(c creds.Bucket) (store.Uploader, error) {
	if c.Vendor != "aws_s3" {
		return nil, fmt.Errorf("unsupported storage service: %q", c.Vendor)
	}
	return b, nil
}

func (b *bucket) UploadRecording(_ context.Context, key string, f *os.File, size int64, info store.CallInfo) error {
	if b.gate != nil {
		<-b.gate
	}
	if b.fail {
		return errors.New("storage unavailable")
	}
	data, err := io.ReadAll(io.NewSectionReader(f, 0, size))
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.objects[key] = data
	b.infos[key] = info
	return nil
}

func (b *bucket) UploadSessionJSON(_ context.Context, key string, body []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.objects[key] = append([]byte(nil), body...)
	return nil
}

func (b *bucket) get(suffix string) (string, []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for k, v := range b.objects {
		if strings.HasSuffix(k, suffix) {
			return k, v
		}
	}
	return "", nil
}

type rig struct {
	t      *testing.T
	srv    *Server
	bucket *bucket
	addr   string
	tmp    string
}

func newRig(t *testing.T, mutate func(*Config)) *rig {
	t.Helper()
	enc, _ := creds.Encrypt(secret, `{"vendor":"aws_s3","name":"b","access_key_id":"k","secret_access_key":"s","region":"us-east-1"}`)
	bad, _ := creds.Encrypt(secret, `{"vendor":"ftp","name":"b"}`)
	b := &bucket{objects: map[string][]byte{}, infos: map[string]store.CallInfo{}}
	cfg := Config{
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Accounts: accounts{
			"acct-wav": {RecordFormat: "wav", BucketCredential: enc},
			"acct-mp3": {RecordFormat: "mp3", BucketCredential: enc},
			"acct-bad": {RecordFormat: "wav", BucketCredential: bad},
		},
		Uploads:          b,
		EncryptionSecret: secret,
		BasicAuthUser:    "user",
		BasicAuthPass:    "pass",
		TmpDir:           t.TempDir(),
		MetadataTimeout:  3 * time.Second,
		EncodeSlots:      2,
		MaxPendingAudio:  1 << 20,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(l)
	r := &rig{t: t, srv: srv, bucket: b, addr: l.Addr().String(), tmp: cfg.TmpDir}
	t.Cleanup(func() { srv.Shutdown(context.Background()) })
	return r
}

func (r *rig) dial() *benchutil.Conn {
	r.t.Helper()
	c, err := benchutil.Dial("ws://"+r.addr+"/record/aws_s3", "user", "pass", 5*time.Second)
	if err != nil {
		r.t.Fatal(err)
	}
	return c
}

// idle waits until every session has been destroyed and checks that no
// spool file was left behind.
func (r *rig) idle() {
	r.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for r.srv.ActiveSessions() != 0 {
		if time.Now().After(deadline) {
			r.t.Fatalf("%d sessions still active", r.srv.ActiveSessions())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if left, _ := os.ReadDir(r.tmp); len(left) != 0 {
		r.t.Errorf("%d spool files left behind", len(left))
	}
}

func metadata(account, callSid string) []byte {
	b, _ := json.Marshal(map[string]any{
		"sampleRate": 8000, "mixType": "stereo", "accountSid": account, "callSid": callSid,
		"direction": "inbound", "from": "+1508", "to": "+1617", "applicationSid": "app",
		"originatingSipIp": "10.0.0.1", "fsSipAddress": "10.0.0.2:5060",
	})
	return b
}

func wav(pcm []byte) []byte {
	h := audio.WAVHeader(uint32(len(pcm)))
	return append(h[:], pcm...)
}

func TestWAVRecordingIsByteExact(t *testing.T) {
	r := newRig(t, nil)
	pcm := benchutil.Speech(8000, 5, 1)
	pcm = append(pcm, 0x7f) // an odd trailing byte is kept in a WAV
	c := r.dial()
	c.Send(wsproto.OpText, metadata("acct-wav", "CA-wav"))
	for off := 0; off < len(pcm); off += 640 {
		c.Send(wsproto.OpBinary, pcm[off:min(off+640, len(pcm))])
		if off == 6400 {
			c.Send(wsproto.OpText, []byte(`{"event":"dtmf","dtmf":"1","duration":120}`))
		}
	}
	c.Send(wsproto.OpText, []byte(`{"type":"session:summary","data":{"call_start":"2020-01-01T00:00:00.000Z","n": 1}}`))
	c.Close()
	r.idle()

	now := time.Now()
	wantKey := fmt.Sprintf("%d/%02d/%02d/CA-wav.wav", now.Year(), int(now.Month()), now.Day())
	key, got := r.bucket.get("CA-wav.wav")
	if key != wantKey {
		t.Errorf("key %q, want %q", key, wantKey)
	}
	if !bytes.Equal(got, wav(pcm)) {
		t.Fatalf("recording differs: %d bytes, want %d", len(got), len(pcm)+44)
	}
	info := r.bucket.infos[key]
	want := store.CallInfo{CallSid: "CA-wav", Direction: "inbound", From: "+1508", To: "+1617",
		ApplicationSid: "app", OriginatingSipIP: "10.0.0.1", OriginatingSipTrunkName: "10.0.0.2:5060", SampleRate: 8000}
	if info != want {
		t.Errorf("call info %+v", info)
	}
	sKey, sBody := r.bucket.get("CA-wav/session.json")
	if !strings.HasSuffix(sKey, "/CA-wav/session.json") {
		t.Fatalf("session.json missing")
	}
	var s map[string]any
	json.Unmarshal(sBody, &s)
	if s["recording_key"] != wantKey || s["n"] != 1.0 || s["recording_started_at_ms"] == nil {
		t.Errorf("session.json %s", sBody)
	}
}

func TestMP3Recording(t *testing.T) {
	if !audio.MP3Supported {
		t.Skip("built with nolame")
	}
	r := newRig(t, nil)
	pcm := benchutil.Speech(8000, 4, 2)
	c := r.dial()
	c.Send(wsproto.OpText, metadata("acct-mp3", "CA-mp3"))
	c.Send(wsproto.OpBinary, pcm)
	c.Close()
	r.idle()
	var want bytes.Buffer
	audio.EncodeMP3(&want, bytes.NewReader(pcm), 8000)
	if _, got := r.bucket.get("CA-mp3.mp3"); !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("mp3 differs: %d bytes, want %d", len(got), want.Len())
	}
}

// An independent client implementation, fragmented messages, pings, audio
// that arrives before the metadata, and a TCP drop instead of a close frame.
func TestInteropWithCoderWebsocket(t *testing.T) {
	r := newRig(t, nil)
	ctx := context.Background()
	c, _, err := websocket.Dial(ctx, "ws://"+r.addr+"/record/aws_s3", &websocket.DialOptions{
		Subprotocols: []string{Subprotocol},
		HTTPHeader:   http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass"))}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.Subprotocol() != Subprotocol {
		t.Fatalf("subprotocol %q", c.Subprotocol())
	}
	go c.Reader(ctx) // lets the client process the pong
	pcm := benchutil.Speech(8000, 3, 3)
	early := pcm[:3200]
	c.Write(ctx, websocket.MessageBinary, early) // before metadata
	// Metadata split across two fragments.
	md := metadata("acct-wav", "CA-coder")
	w, _ := c.Writer(ctx, websocket.MessageText)
	w.Write(md[:20])
	w.Write(md[20:])
	w.Close()
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
	// One large message: the server must stream it, not buffer it.
	c.Write(ctx, websocket.MessageBinary, pcm[3200:])
	c.CloseNow() // no close frame
	r.idle()
	if _, got := r.bucket.get("CA-coder.wav"); !bytes.Equal(got, wav(pcm)) {
		t.Fatalf("recording differs: %d bytes, want %d", len(got), len(pcm)+44)
	}
}

func TestHandshakeRejections(t *testing.T) {
	r := newRig(t, nil)
	try := func(user, pass, proto string) int {
		req, _ := http.NewRequest("GET", "http://"+r.addr+"/record/aws_s3", nil)
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Sec-WebSocket-Version", "13")
		req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		if proto != "" {
			req.Header.Set("Sec-WebSocket-Protocol", proto)
		}
		if user != "" {
			req.SetBasicAuth(user, pass)
		}
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if got := try("user", "pass", "foo, "+Subprotocol); got != http.StatusSwitchingProtocols {
		t.Errorf("valid handshake: %d", got)
	}
	if got := try("", "", Subprotocol); got != http.StatusUnauthorized {
		t.Errorf("no credentials: %d", got)
	}
	if got := try("user", "wrong", Subprotocol); got != http.StatusUnauthorized {
		t.Errorf("wrong password: %d", got)
	}
	if got := try("user", "pass", "foo"); got != http.StatusBadRequest {
		t.Errorf("wrong subprotocol: %d", got)
	}
	if got := try("user", "pass", ""); got != http.StatusBadRequest {
		t.Errorf("no subprotocol: %d", got)
	}
	for path, want := range map[string]int{"/health": 200, "/healthz": 200, "/": 404, "/record": 404} {
		resp, err := http.Get("http://" + r.addr + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != want || (want == 200 && string(body) != "OK") {
			t.Errorf("GET %s: %d %q", path, resp.StatusCode, body)
		}
	}
}

func TestSessionsWithoutARecording(t *testing.T) {
	r := newRig(t, func(c *Config) { c.MetadataTimeout = 150 * time.Millisecond })

	// No metadata: written off after the timeout, later frames ignored.
	silent := r.dial()
	time.Sleep(300 * time.Millisecond)
	if n := r.srv.ActiveSessions(); n != 0 {
		t.Errorf("timed-out session still counted: %d", n)
	}
	silent.Send(wsproto.OpText, metadata("acct-wav", "CA-late"))
	silent.Send(wsproto.OpBinary, make([]byte, 640))
	silent.Close()

	// Unknown account, unsupported vendor, metadata that is not an object.
	for _, md := range [][]byte{metadata("nobody", "CA-x"), metadata("acct-bad", "CA-y"), []byte(`42`)} {
		c := r.dial()
		c.Send(wsproto.OpText, md)
		c.Send(wsproto.OpBinary, make([]byte, 6400))
		c.Close()
	}
	r.idle()
	if len(r.bucket.objects) != 0 {
		t.Errorf("unexpected uploads: %d", len(r.bucket.objects))
	}

	// Metadata but no audio still produces a (header-only) recording.
	c := r.dial()
	c.Send(wsproto.OpText, metadata("acct-wav", "CA-empty"))
	c.Close()
	r.idle()
	if _, got := r.bucket.get("CA-empty.wav"); !bytes.Equal(got, wav(nil)) {
		t.Errorf("empty recording: %d bytes", len(got))
	}
}

func TestFailedUploadCleansUp(t *testing.T) {
	r := newRig(t, nil)
	r.bucket.fail = true
	c := r.dial()
	c.Send(wsproto.OpText, metadata("acct-wav", "CA-fail"))
	c.Send(wsproto.OpBinary, make([]byte, 6400))
	c.Close()
	r.idle()
}

// Shutdown must hang up live calls and still deliver their recordings; slow
// storage must not stop other sessions from being read.
func TestShutdownFinishesRecordings(t *testing.T) {
	r := newRig(t, nil)
	r.bucket.gate = make(chan struct{})
	pcm := benchutil.Speech(8000, 1, 4)

	// One call has ended and is stuck uploading.
	stuck := r.dial()
	stuck.Send(wsproto.OpText, metadata("acct-wav", "CA-stuck"))
	stuck.Send(wsproto.OpBinary, pcm)
	stuck.Close()

	// Meanwhile another call is still live and still being read.
	live := r.dial()
	live.Send(wsproto.OpText, metadata("acct-wav", "CA-live"))
	for off := 0; off < len(pcm); off += 640 {
		if err := live.Send(wsproto.OpBinary, pcm[off:off+640]); err != nil {
			t.Fatal(err)
		}
	}
	// Send() returning proves only that the kernel took the bytes; wait
	// until the server has spooled them all.
	time.Sleep(200 * time.Millisecond)

	done := make(chan error, 1)
	go func() { done <- r.srv.Shutdown(context.Background()) }()
	select {
	case <-done:
		t.Fatal("Shutdown returned while uploads were still blocked")
	case <-time.After(200 * time.Millisecond):
	}
	close(r.bucket.gate)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	for _, sid := range []string{"CA-stuck", "CA-live"} {
		if _, got := r.bucket.get(sid + ".wav"); !bytes.Equal(got, wav(pcm)) {
			t.Errorf("%s: %d bytes, want %d", sid, len(got), len(pcm)+44)
		}
	}
	if _, err := net.DialTimeout("tcp", r.addr, time.Second); err == nil {
		t.Error("still accepting connections after Shutdown")
	}
}

func TestManyConcurrentSessions(t *testing.T) {
	r := newRig(t, nil)
	const n = 64
	pcm := benchutil.Speech(8000, 2, 5)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := benchutil.Dial("ws://"+r.addr+"/", "user", "pass", 5*time.Second)
			if err != nil {
				t.Error(err)
				return
			}
			account := "acct-wav"
			if i%4 == 0 && audio.MP3Supported {
				account = "acct-mp3"
			}
			c.Send(wsproto.OpText, metadata(account, fmt.Sprintf("CA-%03d", i)))
			part := pcm[:len(pcm)-4*i]
			for off := 0; off < len(part); off += 1280 {
				c.Send(wsproto.OpBinary, part[off:min(off+1280, len(part))])
			}
			c.Close()
		}(i)
	}
	wg.Wait()
	r.idle()
	for i := 0; i < n; i++ {
		part := pcm[:len(pcm)-4*i]
		if i%4 == 0 && audio.MP3Supported {
			if _, got := r.bucket.get(fmt.Sprintf("CA-%03d.mp3", i)); len(got) == 0 {
				t.Errorf("session %d: no mp3", i)
			}
			continue
		}
		if _, got := r.bucket.get(fmt.Sprintf("CA-%03d.wav", i)); !bytes.Equal(got, wav(part)) {
			t.Errorf("session %d: %d bytes, want %d", i, len(got), len(part)+44)
		}
	}
}
