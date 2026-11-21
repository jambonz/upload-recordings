package audio

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/jambonz/upload-recordings/go/internal/benchutil"
)

// The header the C++ service's WavHeaderPrepender(8000, 2, 16) writes for
// 0x01020304 bytes of audio.
func TestWAVHeader(t *testing.T) {
	const want = "52494646" + "28030201" + "57415645" + "666d7420" + "10000000" + "0100" + "0200" +
		"401f0000" + "007d0000" + "0400" + "1000" + "64617461" + "04030201"
	h := WAVHeader(0x01020304)
	if got := hex.EncodeToString(h[:]); got != want {
		t.Fatalf("\n got %s\nwant %s", got, want)
	}
}

func TestEncodeMP3(t *testing.T) {
	if !MP3Supported {
		t.Skip("built with nolame")
	}
	for _, rate := range []int{8000, 16000} {
		pcm := benchutil.Speech(rate, 3, 7)
		pcm = append(pcm, 1, 2, 3) // a trailing partial sample frame is dropped
		var out bytes.Buffer
		n, err := EncodeMP3(&out, bytes.NewReader(pcm), rate)
		if err != nil {
			t.Fatal(err)
		}
		if n != int64(len(pcm)-3) {
			t.Errorf("rate %d: consumed %d of %d", rate, n, len(pcm))
		}
		b := out.Bytes()
		if len(b) < 1000 || b[0] != 0xff || b[1]&0xe0 != 0xe0 {
			t.Errorf("rate %d: %d bytes, not starting with an MPEG frame sync", rate, len(b))
		}
		// Same input, same output: chunking must not matter.
		var again bytes.Buffer
		EncodeMP3(&again, bytes.NewReader(pcm), rate)
		if !bytes.Equal(b, again.Bytes()) {
			t.Errorf("rate %d: encoding is not deterministic", rate)
		}
	}
}
