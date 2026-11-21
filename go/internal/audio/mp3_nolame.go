//go:build nolame

package audio

import (
	"errors"
	"io"
)

// MP3Supported reports whether this build can encode MP3.
const MP3Supported = false

// EncodeMP3 always fails in a nolame build: there is no pure-Go encoder that
// matches LAME, so a cgo-free binary can only serve WAV accounts. The server
// logs this at startup and for every MP3 session it has to drop.
func EncodeMP3(io.Writer, io.Reader, int) (int64, error) {
	return 0, errors.New("this binary was built with the nolame tag and cannot encode MP3")
}
