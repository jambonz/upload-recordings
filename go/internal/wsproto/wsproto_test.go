package wsproto

import (
	"bufio"
	"bytes"
	"math/rand/v2"
	"testing"
	"testing/iotest"
)

func TestUnmaskMatchesNaive(t *testing.T) {
	key := [4]byte{0xde, 0xad, 0xbe, 0xef}
	for n := 0; n < 70; n++ {
		for pos := 0; pos < 9; pos++ {
			src := make([]byte, n)
			for i := range src {
				src[i] = byte(rand.Uint32())
			}
			want := make([]byte, n)
			for i := range src {
				want[i] = src[i] ^ key[(pos+i)&3]
			}
			got := append([]byte(nil), src...)
			if end := Unmask(got, key, pos); end != pos+n {
				t.Fatalf("n=%d pos=%d: returned %d", n, pos, end)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("n=%d pos=%d: wrong bytes", n, pos)
			}
		}
	}
}

func frame(op byte, fin bool, payload []byte) []byte {
	key := [4]byte{1, 2, 3, 4}
	b := []byte{op}
	if fin {
		b[0] |= 0x80
	}
	switch n := len(payload); {
	case n < 126:
		b = append(b, 0x80|byte(n))
	case n < 1<<16:
		b = append(b, 0x80|126, byte(n>>8), byte(n))
	default:
		b = append(b, 0x80|127, 0, 0, 0, 0, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	b = append(b, key[:]...)
	masked := append([]byte(nil), payload...)
	Unmask(masked, key, 0)
	return append(b, masked...)
}

func TestReadFrames(t *testing.T) {
	sizes := []int{0, 1, 125, 126, 640, 65535, 65536, 200000}
	var wire bytes.Buffer
	var payloads [][]byte
	for _, n := range sizes {
		p := make([]byte, n)
		for i := range p {
			p[i] = byte(i * 7)
		}
		payloads = append(payloads, p)
		wire.Write(frame(OpBinary, true, p))
	}
	// Deliver one byte at a time through a small buffer to exercise every
	// boundary.
	br := bufio.NewReaderSize(iotest.OneByteReader(&wire), 64)
	for i, want := range payloads {
		h, err := ReadHeader(br)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if h.OpCode != OpBinary || !h.Fin || h.Length != int64(len(want)) {
			t.Fatalf("frame %d: header %+v", i, h)
		}
		var got []byte
		if err := ReadPayload(br, h, func(b []byte) error { got = append(got, b...); return nil }); err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("frame %d: payload differs", i)
		}
	}
}

func TestRejectsBadFrames(t *testing.T) {
	cases := map[string][]byte{
		"unmasked":           {0x82, 0x01, 0xff},
		"reserved bit":       {0xc2, 0x80, 0, 0, 0, 0},
		"fragmented control": {0x09, 0x80, 0, 0, 0, 0},
		"long control":       {0x89, 0xfe, 0, 200, 0, 0, 0, 0},
	}
	for name, b := range cases {
		if _, err := ReadHeader(bufio.NewReader(bytes.NewReader(b))); err != ErrProtocol {
			t.Errorf("%s: got %v, want ErrProtocol", name, err)
		}
	}
}
