// Package benchutil holds what the benchmark and test tools share: a
// synthetic speech-like audio source and a minimal websocket client that
// behaves like the mediajam fork client.
package benchutil

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/jambonz/upload-recordings/go/internal/wsproto"
)

// Speech returns seconds of 16-bit little-endian interleaved stereo PCM that
// is shaped like a two-party phone call: one talker per channel, taking
// turns, voiced harmonics under a syllable-rate envelope, pauses, and a
// little line noise. It is deterministic for a given seed. Silence or a pure
// tone would make the MP3 encoder's work unrepresentatively cheap.
func Speech(rate, seconds int, seed uint64) []byte {
	rng := mrand.New(mrand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	n := rate * seconds
	out := make([]byte, n*4)
	type talker struct {
		pitch, phase, syll float64
		talking            bool
		until              int
	}
	t := [2]talker{{pitch: 115}, {pitch: 205}}
	t[0].talking = true
	for i := 0; i < n; i++ {
		for ch := range t {
			k := &t[ch]
			if i >= k.until { // next turn or pause, 0.4 to 3 seconds
				k.until = i + rate*(4+rng.IntN(27))/10
				k.talking = !t[1-ch].talking && rng.IntN(4) != 0
				k.pitch = k.pitch*0.9 + (90+rng.Float64()*140)*0.1
			}
			v := (rng.Float64() - 0.5) * 60 // line noise
			if k.talking {
				k.phase += 2 * math.Pi * k.pitch / float64(rate)
				k.syll += 2 * math.Pi * 4.2 / float64(rate)
				env := math.Max(0, math.Sin(k.syll)) // ~4 syllables a second
				voiced := 0.0
				for h := 1; h <= 12 && k.pitch*float64(h) < float64(rate)/2-200; h++ {
					voiced += math.Sin(k.phase*float64(h)) / float64(h)
				}
				v += env * (voiced*5200 + (rng.Float64()-0.5)*1800)
			}
			binary.LittleEndian.PutUint16(out[i*4+ch*2:], uint16(int16(math.Max(-32000, math.Min(32000, v)))))
		}
	}
	return out
}

// Conn is a client websocket connection that only ever sends.
type Conn struct {
	c    net.Conn
	mask [4]byte
	buf  []byte
}

// Dial opens a websocket to rawURL (ws://host:port/path) with HTTP Basic
// credentials and the audio.jambonz.org subprotocol.
func Dial(rawURL, user, pass string, timeout time.Duration) (*Conn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	c, err := net.DialTimeout("tcp", u.Host, timeout)
	if err != nil {
		return nil, err
	}
	var nonce [16]byte
	rand.Read(nonce[:])
	path := u.RequestURI()
	req := "GET " + path + " HTTP/1.1\r\nHost: " + u.Host + "\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Key: " + base64.StdEncoding.EncodeToString(nonce[:]) + "\r\n" +
		"Sec-WebSocket-Protocol: audio.jambonz.org\r\n" +
		"Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass)) + "\r\n\r\n"
	c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write([]byte(req)); err != nil {
		c.Close()
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		c.Close()
		return nil, fmt.Errorf("handshake: HTTP %d", resp.StatusCode)
	}
	c.SetDeadline(time.Time{})
	conn := &Conn{c: c}
	rand.Read(conn.mask[:])
	return conn, nil
}

// AppendFrame appends one masked frame to dst.
func AppendFrame(dst []byte, op byte, mask [4]byte, payload []byte) []byte {
	dst = append(dst, 0x80|op)
	switch n := len(payload); {
	case n < 126:
		dst = append(dst, 0x80|byte(n))
	case n < 1<<16:
		dst = append(dst, 0x80|126, byte(n>>8), byte(n))
	default:
		dst = append(dst, 0x80|127)
		dst = binary.BigEndian.AppendUint64(dst, uint64(n))
	}
	dst = append(dst, mask[:]...)
	start := len(dst)
	dst = append(dst, payload...)
	wsproto.Unmask(dst[start:], mask, 0)
	return dst
}

// Send writes one frame.
func (c *Conn) Send(op byte, payload []byte) error {
	c.buf = AppendFrame(c.buf[:0], op, c.mask, payload)
	_, err := c.c.Write(c.buf)
	return err
}

// Mask is the connection's masking key.
func (c *Conn) Mask() [4]byte { return c.mask }

// WriteRaw writes pre-built frames.
func (c *Conn) WriteRaw(b []byte) error {
	_, err := c.c.Write(b)
	return err
}

// Close sends a close frame, waits briefly for the peer's, and closes.
func (c *Conn) Close() error {
	c.Send(wsproto.OpClose, []byte{0x03, 0xe8})
	c.c.SetReadDeadline(time.Now().Add(2 * time.Second))
	var b [64]byte
	c.c.Read(b[:])
	return c.c.Close()
}

// Abort closes the TCP connection without a close frame.
func (c *Conn) Abort() error { return c.c.Close() }
