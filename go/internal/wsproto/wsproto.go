// Package wsproto is the server receive side of RFC 6455, and nothing more.
//
// The recording server only ever reads: clients push one small binary frame
// per 20 ms of audio and the server never sends data back. A general-purpose
// websocket library pays for features this path does not use (per-message
// readers, write locks, context plumbing), so the frame parser lives here:
// it works directly on the connection's bufio.Reader, allocates nothing per
// frame, and hands payload bytes to the caller without copying them.
package wsproto

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Opcodes (RFC 6455 section 5.2).
const (
	OpContinuation = 0x0
	OpText         = 0x1
	OpBinary       = 0x2
	OpClose        = 0x8
	OpPing         = 0x9
	OpPong         = 0xA
)

const acceptGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// ErrProtocol is returned for frames a compliant client never sends.
var ErrProtocol = errors.New("websocket protocol error")

// Header is one parsed frame header.
type Header struct {
	Fin    bool
	OpCode byte
	Length int64
	Mask   [4]byte
}

// IsUpgrade reports whether r asks for a websocket upgrade.
func IsUpgrade(r *http.Request) bool {
	return headerHasToken(r.Header, "Connection", "upgrade") &&
		strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

// OffersProtocol reports whether the client listed name in
// Sec-WebSocket-Protocol.
func OffersProtocol(r *http.Request, name string) bool {
	return headerHasToken(r.Header, "Sec-Websocket-Protocol", name)
}

func headerHasToken(h http.Header, key, token string) bool {
	for _, v := range h.Values(key) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

// Accept completes the opening handshake, selecting subprotocol, and returns
// the hijacked connection together with the reader that must be used for all
// further reads (it may already hold bytes the client sent after its request).
func Accept(w http.ResponseWriter, r *http.Request, subprotocol string) (net.Conn, *bufio.Reader, error) {
	key := r.Header.Get("Sec-Websocket-Key")
	if r.Method != http.MethodGet || key == "" || r.Header.Get("Sec-Websocket-Version") != "13" {
		http.Error(w, "bad websocket handshake", http.StatusBadRequest)
		return nil, nil, fmt.Errorf("%w: bad handshake", ErrProtocol)
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "cannot hijack", http.StatusInternalServerError)
		return nil, nil, errors.New("response writer is not a hijacker")
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return nil, nil, err
	}
	sum := sha1.Sum([]byte(key + acceptGUID))
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(sum[:]) + "\r\n" +
		"Sec-WebSocket-Protocol: " + subprotocol + "\r\n\r\n"
	// The server's connection deadlines do not apply once hijacked.
	conn.SetDeadline(time.Time{})
	if _, err := io.WriteString(conn, resp); err != nil {
		conn.Close()
		return nil, nil, err
	}
	return conn, rw.Reader, nil
}

// ReadHeader parses the next frame header. Client frames must be masked and
// must not use reserved bits (no extension is ever negotiated).
func ReadHeader(br *bufio.Reader) (Header, error) {
	var h Header
	b, err := br.Peek(2)
	if err != nil {
		return h, err
	}
	if b[0]&0x70 != 0 || b[1]&0x80 == 0 {
		return h, ErrProtocol
	}
	h.Fin = b[0]&0x80 != 0
	h.OpCode = b[0] & 0x0f
	l := int(b[1] & 0x7f)
	n := 2
	switch l {
	case 126:
		n += 2
	case 127:
		n += 8
	}
	b, err = br.Peek(n + 4)
	if err != nil {
		return h, err
	}
	switch l {
	case 126:
		h.Length = int64(binary.BigEndian.Uint16(b[2:4]))
	case 127:
		u := binary.BigEndian.Uint64(b[2:10])
		if u > 1<<62 {
			return h, ErrProtocol
		}
		h.Length = int64(u)
	default:
		h.Length = int64(l)
	}
	copy(h.Mask[:], b[n:n+4])
	if h.OpCode >= OpClose && (!h.Fin || h.Length > 125) {
		return h, ErrProtocol
	}
	_, err = br.Discard(n + 4)
	return h, err
}

// ReadPayload feeds the frame's unmasked payload to fn in whatever pieces
// the reader has buffered. The slice passed to fn aliases the reader's buffer
// and is only valid until fn returns.
func ReadPayload(br *bufio.Reader, h Header, fn func([]byte) error) error {
	remaining := h.Length
	pos := 0
	for remaining > 0 {
		if br.Buffered() == 0 {
			if _, err := br.Peek(1); err != nil {
				return unexpected(err)
			}
		}
		n := br.Buffered()
		if int64(n) > remaining {
			n = int(remaining)
		}
		p, err := br.Peek(n)
		if err != nil {
			return unexpected(err)
		}
		pos = Unmask(p, h.Mask, pos)
		if fn != nil {
			if err := fn(p); err != nil {
				return err
			}
		}
		br.Discard(n)
		remaining -= int64(n)
	}
	return nil
}

func unexpected(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

// Unmask XORs b in place with the masking key, starting at key offset pos,
// and returns the offset to continue from.
func Unmask(b []byte, key [4]byte, pos int) int {
	// Bring pos to a key boundary, then work a word at a time.
	for len(b) > 0 && pos&3 != 0 {
		b[0] ^= key[pos&3]
		b = b[1:]
		pos++
	}
	k32 := binary.LittleEndian.Uint32(key[:])
	k64 := uint64(k32)<<32 | uint64(k32)
	for len(b) >= 8 {
		binary.LittleEndian.PutUint64(b, binary.LittleEndian.Uint64(b)^k64)
		b = b[8:]
		pos += 8
	}
	for i := range b {
		b[i] ^= key[(pos+i)&3]
	}
	return pos + len(b)
}

// WriteControl sends an unmasked control frame (pong or close).
func WriteControl(conn net.Conn, op byte, payload []byte) error {
	if len(payload) > 125 {
		payload = payload[:125]
	}
	buf := make([]byte, 2, 2+len(payload))
	buf[0] = 0x80 | op
	buf[1] = byte(len(payload))
	buf = append(buf, payload...)
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := conn.Write(buf)
	return err
}
