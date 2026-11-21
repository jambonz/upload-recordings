//go:build !nolame

package audio

/*
#cgo LDFLAGS: -lmp3lame
#cgo darwin CFLAGS: -I/opt/homebrew/include -I/usr/local/include
#cgo darwin LDFLAGS: -L/opt/homebrew/lib -L/usr/local/lib
#include <lame/lame.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"io"
	"unsafe"
)

// MP3Supported reports whether this build can encode MP3.
const MP3Supported = true

// Bytes of PCM handed to LAME per call. LAME frames its input internally, so
// the output does not depend on this; it only sets how much memory an
// in-flight encode holds (this plus the MP3 buffer, about 600 KB).
const pcmChunk = 256 * 1024

// EncodeMP3 encodes 16-bit little-endian interleaved stereo PCM from r into
// w, with the same LAME settings as the C++ service: 2 channels, 128 kbit/s
// requested, stereo mode, quality 2. A trailing partial sample frame is
// dropped. It returns the number of PCM bytes consumed.
func EncodeMP3(w io.Writer, r io.Reader, sampleRate int) (int64, error) {
	gfp := C.lame_init()
	if gfp == nil {
		return 0, errors.New("failed to initialize LAME encoder")
	}
	defer C.lame_close(gfp)

	C.lame_set_in_samplerate(gfp, C.int(sampleRate))
	C.lame_set_num_channels(gfp, 2)
	C.lame_set_brate(gfp, 128)
	C.lame_set_mode(gfp, C.STEREO)
	C.lame_set_quality(gfp, 2)
	if C.lame_init_params(gfp) < 0 {
		return 0, fmt.Errorf("failed to set LAME encoder parameters (sample rate %d)", sampleRate)
	}

	const bytesPerFrame = 4 // 2 channels x 16 bit
	pcm := make([]byte, pcmChunk)
	// LAME's documented worst case: 1.25 * samples + 7200.
	mp3 := make([]byte, pcmChunk/bytesPerFrame*5/4+7200)
	mp3p := (*C.uchar)(unsafe.Pointer(&mp3[0]))

	var consumed int64
	for {
		n, rerr := io.ReadFull(r, pcm)
		n -= n % bytesPerFrame
		if n > 0 {
			out := C.lame_encode_buffer_interleaved(gfp,
				(*C.short)(unsafe.Pointer(&pcm[0])), C.int(n/bytesPerFrame), mp3p, C.int(len(mp3)))
			if out < 0 {
				return consumed, fmt.Errorf("failed to encode MP3 data (lame error %d)", int(out))
			}
			if _, err := w.Write(mp3[:out]); err != nil {
				return consumed, err
			}
			consumed += int64(n)
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			return consumed, rerr
		}
	}
	out := C.lame_encode_flush(gfp, mp3p, C.int(len(mp3)))
	if out < 0 {
		return consumed, errors.New("failed to finalize MP3 encoding")
	}
	_, err := w.Write(mp3[:out])
	return consumed, err
}
