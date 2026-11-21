// Package audio turns the raw PCM a session spooled to disk into the WAV or
// MP3 object that is uploaded.
package audio

import "encoding/binary"

// WAVHeaderLen is the size of the canonical 44-byte PCM WAV header.
const WAVHeaderLen = 44

// WAVHeader returns the header for dataSize bytes of audio.
//
// The format fields are fixed at 8 kHz, 2 channels, 16 bit: the C++ service
// hard-codes them and ignores the sampleRate the client sent, and recordings
// must stay byte-identical with it. That is only correct because jambonz
// always records at 8 kHz stereo; see BENCHMARKS.md ("Behaviour found").
func WAVHeader(dataSize uint32) [WAVHeaderLen]byte {
	const (
		sampleRate    = 8000
		channels      = 2
		bitsPerSample = 16
	)
	var h [WAVHeaderLen]byte
	copy(h[0:], "RIFF")
	binary.LittleEndian.PutUint32(h[4:], 36+dataSize)
	copy(h[8:], "WAVE")
	copy(h[12:], "fmt ")
	binary.LittleEndian.PutUint32(h[16:], 16) // PCM fmt chunk size
	binary.LittleEndian.PutUint16(h[20:], 1)  // PCM
	binary.LittleEndian.PutUint16(h[22:], channels)
	binary.LittleEndian.PutUint32(h[24:], sampleRate)
	binary.LittleEndian.PutUint32(h[28:], sampleRate*channels*bitsPerSample/8)
	binary.LittleEndian.PutUint16(h[32:], channels*bitsPerSample/8)
	binary.LittleEndian.PutUint16(h[34:], bitsPerSample)
	copy(h[36:], "data")
	binary.LittleEndian.PutUint32(h[40:], dataSize)
	return h
}
