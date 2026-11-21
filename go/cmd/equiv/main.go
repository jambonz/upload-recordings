// Command equiv checks that two implementations of the recording server
// store the same objects for the same websocket session.
//
//	equiv run -url ws://server:3017 -out /results/equiv/cpp   # play, fetch, delete
//	equiv diff /results/equiv/cpp /results/equiv/go            # compare
//
// "run" plays a fixed, deterministic set of sessions and saves every object
// the server wrote, with its content type and user metadata. "diff" requires
// WAV recordings to be byte-identical and MP3 recordings to have the same
// sample rate, channel mode, bitrate and duration.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/jambonz/upload-recordings/go/internal/benchutil"
	"github.com/jambonz/upload-recordings/go/internal/wsproto"
)

type testCase struct {
	name        string
	account     string
	rate        int
	seconds     int
	extraBytes  int  // odd bytes appended to the audio
	earlyAudio  bool // send a little audio before the metadata
	splitMeta   bool // metadata as two text frames
	abort       bool // drop TCP instead of a close frame
	summary     bool
	frameBytes  int
	noSampleKey bool
}

var cases = []testCase{
	{name: "wav-8k", account: "acct-wav", rate: 8000, seconds: 20, summary: true, frameBytes: 640},
	{name: "wav-16k", account: "acct-wav", rate: 16000, seconds: 10, frameBytes: 1280},
	{name: "wav-odd-tail", account: "acct-wav", rate: 8000, seconds: 3, extraBytes: 3, frameBytes: 640},
	{name: "wav-early-audio-split-meta", account: "acct-wav", rate: 8000, seconds: 3, earlyAudio: true, splitMeta: true, frameBytes: 640},
	{name: "wav-abort", account: "acct-wav", rate: 8000, seconds: 3, abort: true, frameBytes: 640},
	{name: "wav-big-frames", account: "acct-wav", rate: 8000, seconds: 40, frameBytes: 100000},
	{name: "wav-no-audio", account: "acct-wav", rate: 8000, seconds: 0, frameBytes: 640},
	{name: "mp3-8k", account: "acct-mp3", rate: 8000, seconds: 20, summary: true, frameBytes: 640},
	{name: "mp3-16k", account: "acct-mp3", rate: 16000, seconds: 20, frameBytes: 1280},
	{name: "mp3-odd-tail", account: "acct-mp3", rate: 8000, seconds: 5, extraBytes: 3, frameBytes: 640},
	{name: "mp3-long", account: "acct-mp3", rate: 8000, seconds: 200, frameBytes: 640},
}

type saved struct {
	Key         string            `json:"key"`
	Size        int64             `json:"size"`
	ContentType string            `json:"content_type"`
	Metadata    map[string]string `json:"metadata"`
	File        string            `json:"file"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: equiv run|diff ...")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run":
		run(os.Args[2:])
	case "diff":
		if len(os.Args) != 4 {
			fmt.Fprintln(os.Stderr, "usage: equiv diff DIR_A DIR_B")
			os.Exit(2)
		}
		if !diff(os.Args[2], os.Args[3]) {
			os.Exit(1)
		}
	}
}

func run(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	target := fs.String("url", "ws://ur-sut:3017", "recording server")
	out := fs.String("out", "", "directory to save objects to")
	s3URL := fs.String("s3", "https://minio:9000", "S3 endpoint")
	bucket := fs.String("bucket", "recordings", "bucket")
	fs.Parse(args)
	os.MkdirAll(*out, 0o755)

	for _, tc := range cases {
		if err := play(*target, tc); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", tc.name, err)
			os.Exit(1)
		}
	}

	client := s3.New(s3.Options{
		Region: "us-east-1", BaseEndpoint: s3URL, UsePathStyle: true,
		Credentials: credentials.NewStaticCredentialsProvider("minioadmin", "minioadmin", ""),
	})
	ctx := context.Background()
	want := 0
	for _, tc := range cases {
		want++
		if tc.summary {
			want++
		}
	}
	var keys []string
	for deadline := time.Now().Add(90 * time.Second); ; {
		keys = keys[:0]
		p := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{Bucket: bucket})
		for p.HasMorePages() {
			page, err := p.NextPage(ctx)
			if err != nil {
				fmt.Fprintln(os.Stderr, "list:", err)
				os.Exit(1)
			}
			for _, o := range page.Contents {
				if strings.Contains(*o.Key, "/equiv-") {
					keys = append(keys, *o.Key)
				}
			}
		}
		if len(keys) >= want || time.Now().After(deadline) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	time.Sleep(time.Second) // let any stragglers (unexpected extra objects) land
	sort.Strings(keys)
	var index []saved
	for _, k := range keys {
		obj, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: bucket, Key: &k})
		if err != nil {
			fmt.Fprintln(os.Stderr, "get:", err)
			os.Exit(1)
		}
		body, _ := io.ReadAll(obj.Body)
		obj.Body.Close()
		// Strip the date so runs on different days compare.
		name := strings.ReplaceAll(k[len("2006/01/02/"):], "/", "_")
		os.WriteFile(filepath.Join(*out, name), body, 0o644)
		index = append(index, saved{k[len("2006/01/02/"):], int64(len(body)), aws.ToString(obj.ContentType), obj.Metadata, name})
		client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: bucket, Key: &k})
	}
	b, _ := json.MarshalIndent(index, "", "  ")
	os.WriteFile(filepath.Join(*out, "index.json"), b, 0o644)
	fmt.Printf("saved %d objects (expected %d) to %s\n", len(index), want, *out)
}

func play(target string, tc testCase) error {
	c, err := benchutil.Dial(target+"/record/s3_compatible", "bench", "bench", 10*time.Second)
	if err != nil {
		return err
	}
	sid := "equiv-" + tc.name
	meta, _ := json.Marshal(map[string]any{
		"sampleRate": tc.rate, "mixType": "stereo", "accountSid": tc.account, "callSid": sid,
		"direction": "inbound", "from": "+15083084809", "to": "+15085551212",
		"applicationSid": "0e0681b0-d49f-4fb8-b973-b5a3c6758de1", "originatingSipIp": "10.0.0.1",
		"fsSipAddress": "10.0.0.2:5060",
	})
	pcm := benchutil.Speech(tc.rate, max(tc.seconds, 1), 42)[:tc.rate*4*tc.seconds]
	pcm = append(pcm, make([]byte, tc.extraBytes)...)
	if tc.earlyAudio {
		c.Send(wsproto.OpBinary, pcm[:1280])
		pcm = pcm[1280:]
	}
	if tc.splitMeta {
		half := len(meta) / 2
		c.WriteRaw(benchutil.AppendFrame(nil, wsproto.OpText, c.Mask(), meta[:half])) // sent as a whole frame...
		c.Send(wsproto.OpText, meta[half:])                                           // ...then the rest as another
	} else {
		c.Send(wsproto.OpText, meta)
	}
	// Give the server time to resolve the account: the C++ service drops
	// audio that arrives faster than it can be flushed (3 MB buffer).
	time.Sleep(300 * time.Millisecond)
	for off := 0; off < len(pcm); off += tc.frameBytes {
		if err := c.Send(wsproto.OpBinary, pcm[off:min(off+tc.frameBytes, len(pcm))]); err != nil {
			return err
		}
		if off/tc.frameBytes%50 == 49 {
			time.Sleep(2 * time.Millisecond) // ~500x real time
		}
		if off == tc.frameBytes*10 {
			c.Send(wsproto.OpText, []byte(`{"event":"dtmf","dtmf":"5","duration":160}`))
		}
	}
	if tc.summary {
		c.Send(wsproto.OpText, []byte(`{"type":"session:summary","data":{"call_sid":"`+sid+
			`","call_start":"2020-01-01T00:00:00.250Z","duration":12.50,"turns":[{"transcript":"héllo","response":"hi"}]}}`))
	}
	if tc.abort {
		return c.Abort()
	}
	return c.Close()
}

// mp3Info walks the MPEG audio frames in b.
type mp3Info struct {
	SampleRate int
	Mode       string
	Bitrate    int
	Frames     int
	Seconds    float64
}

func parseMP3(b []byte) (mp3Info, error) {
	var info mp3Info
	rates := map[byte][3]int{3: {44100, 48000, 32000}, 2: {22050, 24000, 16000}, 0: {11025, 12000, 8000}}
	br1 := [16]int{0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0}
	br2 := [16]int{0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0}
	modes := [4]string{"stereo", "joint stereo", "dual channel", "mono"}
	samples := 0
	for i := 0; i+4 <= len(b); {
		if b[i] != 0xff || b[i+1]&0xe0 != 0xe0 {
			return info, fmt.Errorf("lost frame sync at byte %d", i)
		}
		version := b[i+1] >> 3 & 3
		layer := b[i+1] >> 1 & 3
		brIdx, srIdx, pad := b[i+2]>>4, b[i+2]>>2&3, int(b[i+2]>>1&1)
		if layer != 1 || version == 1 || srIdx == 3 || brIdx == 0 || brIdx == 15 {
			return info, fmt.Errorf("unsupported frame header at byte %d", i)
		}
		sr := rates[version][srIdx]
		kbps, perFrame, coef := br1[brIdx], 1152, 144
		if version != 3 {
			kbps, perFrame, coef = br2[brIdx], 576, 72
		}
		if info.Frames == 0 {
			info.SampleRate, info.Bitrate, info.Mode = sr, kbps, modes[b[i+3]>>6]
		} else if sr != info.SampleRate || kbps != info.Bitrate {
			return info, fmt.Errorf("frame %d changes rate/bitrate", info.Frames)
		}
		info.Frames++
		samples += perFrame
		i += coef*kbps*1000/sr + pad
	}
	if info.Frames == 0 {
		return info, fmt.Errorf("no MPEG frames")
	}
	info.Seconds = float64(samples) / float64(info.SampleRate)
	return info, nil
}

func load(dir string) map[string]saved {
	b, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var index []saved
	json.Unmarshal(b, &index)
	m := map[string]saved{}
	for _, s := range index {
		m[s.Key] = s
	}
	return m
}

func diff(dirA, dirB string) bool {
	a, b := load(dirA), load(dirB)
	keys := map[string]bool{}
	for k := range a {
		keys[k] = true
	}
	for k := range b {
		keys[k] = true
	}
	var sorted []string
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	ok := true
	fail := func(k, format string, args ...any) {
		ok = false
		fmt.Printf("FAIL  %-44s %s\n", k, fmt.Sprintf(format, args...))
	}
	for _, k := range sorted {
		oa, inA := a[k]
		ob, inB := b[k]
		if !inA || !inB {
			fail(k, "present in A: %v, in B: %v", inA, inB)
			continue
		}
		da, _ := os.ReadFile(filepath.Join(dirA, oa.File))
		db, _ := os.ReadFile(filepath.Join(dirB, ob.File))
		if oa.ContentType != ob.ContentType {
			fail(k, "content type %q vs %q", oa.ContentType, ob.ContentType)
		}
		ma, _ := json.Marshal(oa.Metadata)
		mb, _ := json.Marshal(ob.Metadata)
		if !bytes.Equal(ma, mb) {
			fail(k, "metadata %s vs %s", ma, mb)
		}
		switch {
		case strings.HasSuffix(k, ".wav"):
			if !bytes.Equal(da, db) {
				fail(k, "WAV differs (%d vs %d bytes)", len(da), len(db))
				continue
			}
			fmt.Printf("ok    %-44s byte-identical, %d bytes, %s %s\n", k, len(da), oa.ContentType, ma)
		case strings.HasSuffix(k, ".mp3"):
			ia, errA := parseMP3(da)
			ib, errB := parseMP3(db)
			if errA != nil || errB != nil {
				fail(k, "MP3 parse: %v / %v", errA, errB)
				continue
			}
			if ia != ib {
				fail(k, "MP3 differs: %+v vs %+v", ia, ib)
				continue
			}
			same := "bytes differ"
			if bytes.Equal(da, db) {
				same = "byte-identical"
			}
			fmt.Printf("ok    %-44s %d Hz %s %d kbit/s %.3f s, %s\n", k, ia.SampleRate, ia.Mode, ia.Bitrate, ia.Seconds, same)
		case strings.HasSuffix(k, "session.json"):
			var ja, jb map[string]any
			json.Unmarshal(da, &ja)
			json.Unmarshal(db, &jb)
			// The offset depends on when each run happened.
			_, hasA := ja["recording_started_at_ms"]
			_, hasB := jb["recording_started_at_ms"]
			delete(ja, "recording_started_at_ms")
			delete(jb, "recording_started_at_ms")
			na, _ := json.Marshal(ja)
			nb, _ := json.Marshal(jb)
			if !bytes.Equal(na, nb) || hasA != hasB {
				fail(k, "session.json differs:\n  A %s\n  B %s", da, db)
				continue
			}
			fmt.Printf("ok    %-44s same members; A: %s\n", k, da)
			if !bytes.Equal(stripOffset(da), stripOffset(db)) {
				fmt.Printf("note  %-44s serialization differs; B: %s\n", k, db)
			}
		}
	}
	return ok
}

// stripOffset removes the trailing recording_started_at_ms member textually.
func stripOffset(b []byte) []byte {
	if i := bytes.Index(b, []byte(`,"recording_started_at_ms":`)); i >= 0 {
		return b[:i]
	}
	return b
}
