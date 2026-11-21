// Command loadgen drives the recording server the way jambonz does: N
// concurrent websocket sessions, each sending a metadata frame and then one
// 20 ms binary frame of stereo PCM at a time, in real time. When the calls
// end it finds every recording in the bucket and reports how long each took
// to appear and whether any audio went missing.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/jambonz/upload-recordings/go/internal/benchutil"
	"github.com/jambonz/upload-recordings/go/internal/wsproto"
)

type result struct {
	Label       string  `json:"label"`
	Sessions    int     `json:"sessions"`
	Rate        int     `json:"rate"`
	CallSecs    float64 `json:"call_secs"`
	Blast       bool    `json:"blast"`
	ConnectErrs int64   `json:"connect_errors"`
	SendErrs    int64   `json:"send_errors"`
	LateFrames  int64   `json:"late_frames"`   // frames sent more than 100 ms behind schedule
	MaxLateMs   int64   `json:"max_late_ms"`   // worst sender lag (TCP backpressure from the server)
	BytesSent   int64   `json:"bytes_sent"`    // audio bytes accepted by the socket
	SendSecs    float64 `json:"send_secs"`     // first connect to last close
	Found       int     `json:"objects_found"` // recordings present in the bucket
	Missing     int     `json:"objects_missing"`
	Short       int     `json:"objects_short"` // recordings with less audio than was sent
	BytesLost   int64   `json:"audio_bytes_lost"`
	Summaries   int     `json:"session_json_found"`
	LatencyMs   pcts    `json:"latency_ms"` // last frame sent -> object LastModified
	AllDoneSecs float64 `json:"all_done_secs"`
	IngestMBps  float64 `json:"ingest_mb_per_sec"` // blast mode: audio landed in objects / send time
}

type pcts struct {
	Min, P50, P95, P99, Max float64
}

type sessionResult struct {
	callSid  string
	sent     int64
	closedAt time.Time
	ok       bool
}

func main() {
	var (
		target   = flag.String("url", "ws://127.0.0.1:3017", "recording server base URL")
		user     = flag.String("user", "bench", "basic auth user")
		pass     = flag.String("pass", "bench", "basic auth password")
		account  = flag.String("account", "acct-wav", "account_sid to record under")
		format   = flag.String("format", "wav", "expected object format: wav or mp3")
		sessions = flag.Int("sessions", 10, "concurrent sessions")
		rate     = flag.Int("rate", 8000, "sample rate: 8000 or 16000")
		callSecs = flag.Float64("call", 60, "call length in seconds")
		jitter   = flag.Float64("jitter", 0.2, "call length varies by +/- this fraction")
		ramp     = flag.Float64("ramp", 10, "seconds over which sessions start")
		blast    = flag.Bool("blast", false, "send as fast as the server accepts instead of in real time")
		summary  = flag.Bool("summary", true, "send a session:summary frame before hanging up")
		label    = flag.String("label", "", "label copied into the result")
		runID    = flag.String("run", fmt.Sprintf("%d", time.Now().UnixNano()), "unique id used in call sids")
		wait     = flag.Duration("wait", 5*time.Minute, "how long to wait for recordings to appear")
		s3URL    = flag.String("s3", "https://minio:9000", "S3 endpoint to verify against (empty: skip)")
		s3Key    = flag.String("s3-key", "minioadmin", "S3 access key")
		s3Secret = flag.String("s3-secret", "minioadmin", "S3 secret key")
		bucket   = flag.String("bucket", "recordings", "bucket")
		cleanup  = flag.Bool("cleanup", true, "delete the run's objects afterwards")
		outPath  = flag.String("out", "", "also append the JSON result to this file")
		frameMs  = flag.Int("frame-ms", 20, "frame duration")
		abort    = flag.Bool("abort", false, "drop the TCP connection instead of a websocket close")
	)
	flag.Parse()

	audio := benchutil.Speech(*rate, 20, 1)
	frameBytes := *rate * 4 * *frameMs / 1000
	res := result{Label: *label, Sessions: *sessions, Rate: *rate, CallSecs: *callSecs, Blast: *blast}

	results := make([]sessionResult, *sessions)
	var wg sync.WaitGroup
	var maxLate atomic.Int64
	start := time.Now()
	for i := 0; i < *sessions; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r := &results[i]
			r.callSid = fmt.Sprintf("bench-%s-%05d", *runID, i)
			time.Sleep(time.Duration(float64(i) / float64(*sessions) * *ramp * float64(time.Second)))
			conn, err := benchutil.Dial(*target+"/record/s3_compatible", *user, *pass, 20*time.Second)
			if err != nil {
				atomic.AddInt64(&res.ConnectErrs, 1)
				fmt.Fprintln(os.Stderr, "connect:", err)
				return
			}
			meta, _ := json.Marshal(map[string]any{
				"sampleRate": *rate, "mixType": "stereo", "accountSid": *account, "callSid": r.callSid,
				"direction": "inbound", "from": "+15083084809", "to": "+15085551212",
				"applicationSid": "0e0681b0-d49f-4fb8-b973-b5a3c6758de1", "originatingSipIp": "10.0.0.1",
				"fsSipAddress": "10.0.0.2:5060", "callId": r.callSid + "@10.0.0.1", "traceId": "00000000",
			})
			if err := conn.Send(wsproto.OpText, meta); err != nil {
				atomic.AddInt64(&res.SendErrs, 1)
				return
			}
			length := *callSecs * (1 + *jitter*(2*rand.Float64()-1))
			pos := rand.IntN(len(audio)/4) * 4
			next := func(n int) []byte {
				if pos+n > len(audio) {
					pos = 0
				}
				p := audio[pos : pos+n]
				pos += n
				return p
			}
			callStart := time.Now()
			failed := false
			if *blast {
				// A fixed batch of pre-masked frames, written over and over.
				var batch []byte
				for len(batch) < 256*1024 {
					batch = benchutil.AppendFrame(batch, wsproto.OpBinary, conn.Mask(), next(frameBytes))
				}
				perBatch := int64(len(batch) / (frameBytes + 8) * frameBytes)
				for time.Since(callStart).Seconds() < length {
					if err := conn.WriteRaw(batch); err != nil {
						failed = true
						break
					}
					r.sent += perBatch
				}
			} else {
				frames := int(length * 1000 / float64(*frameMs))
				for f := 0; f < frames; f++ {
					due := callStart.Add(time.Duration(f**frameMs) * time.Millisecond)
					if d := time.Until(due); d > 0 {
						time.Sleep(d)
					} else if late := -d.Milliseconds(); late > 100 {
						atomic.AddInt64(&res.LateFrames, 1)
						for {
							cur := maxLate.Load()
							if late <= cur || maxLate.CompareAndSwap(cur, late) {
								break
							}
						}
					}
					if err := conn.Send(wsproto.OpBinary, next(frameBytes)); err != nil {
						failed = true
						break
					}
					r.sent += int64(frameBytes)
					if f == frames/2 { // jambonz forwards DTMF as text frames (passDtmf)
						conn.Send(wsproto.OpText, []byte(`{"event":"dtmf","dtmf":"5","duration":160}`))
					}
				}
			}
			if failed {
				atomic.AddInt64(&res.SendErrs, 1)
			}
			if *summary && !failed {
				s, _ := json.Marshal(map[string]any{"type": "session:summary", "data": map[string]any{
					"call_sid": r.callSid, "account_sid": *account,
					"call_start": callStart.UTC().Format("2006-01-02T15:04:05.000Z"),
					"turns":      []map[string]any{{"transcript": "hello", "response": "hi there", "start_ms": 1200}},
				}})
				conn.Send(wsproto.OpText, s)
			}
			r.closedAt = time.Now()
			if *abort {
				conn.Abort()
			} else {
				conn.Close()
			}
			r.ok = true
			atomic.AddInt64(&res.BytesSent, r.sent)
		}(i)
	}
	wg.Wait()
	res.SendSecs = time.Since(start).Seconds()
	res.MaxLateMs = maxLate.Load()
	fmt.Fprintf(os.Stderr, "[%s] sent %d sessions in %.1fs, waiting for objects\n", *label, *sessions, res.SendSecs)

	if *s3URL != "" {
		verify(&res, results, *s3URL, *s3Key, *s3Secret, *bucket, *format, *runID, *rate, *wait, *cleanup, start)
	}
	out, _ := json.Marshal(res)
	fmt.Println(string(out))
	if *outPath != "" {
		f, err := os.OpenFile(*outPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err == nil {
			f.Write(append(out, '\n'))
			f.Close()
		}
	}
}

type object struct {
	size     int64
	modified time.Time
}

func verify(res *result, sessions []sessionResult, endpoint, key, secret, bucket, format, runID string,
	rate int, wait time.Duration, cleanup bool, start time.Time) {
	client := s3.New(s3.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(endpoint),
		UsePathStyle: true,
		Credentials:  credentials.NewStaticCredentialsProvider(key, secret, ""),
	})
	ctx := context.Background()
	want := 0
	for _, s := range sessions {
		if s.ok {
			want++
		}
	}
	// Recordings are keyed by the server's local date at upload time; the
	// run id makes the call sids unique, so list by the date prefixes the
	// run can span.
	list := func() (map[string]object, int) {
		found := map[string]object{}
		seen := map[string]bool{}
		for _, day := range []time.Time{start, time.Now()} {
			prefix := fmt.Sprintf("%d/%02d/%02d/bench-%s-", day.Year(), int(day.Month()), day.Day(), runID)
			if seen[prefix] {
				continue
			}
			seen[prefix] = true
			p := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{Bucket: &bucket, Prefix: &prefix})
			for p.HasMorePages() {
				page, err := p.NextPage(ctx)
				if err != nil {
					fmt.Fprintln(os.Stderr, "list:", err)
					break
				}
				for _, o := range page.Contents {
					k := *o.Key
					found[k] = object{*o.Size, *o.LastModified}
				}
			}
		}
		summaries := 0
		for k := range found {
			if strings.HasSuffix(k, "/session.json") {
				summaries++
			}
		}
		return found, summaries
	}
	deadline := time.Now().Add(wait)
	var found map[string]object
	for {
		found, res.Summaries = list()
		if len(found)-res.Summaries >= want || time.Now().After(deadline) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	// session.json lands just after its recording; give the last ones a moment.
	if res.Summaries < want {
		time.Sleep(2 * time.Second)
		found, res.Summaries = list()
	}
	res.AllDoneSecs = time.Since(start).Seconds()

	bySid := map[string]object{}
	for k, o := range found {
		if strings.HasSuffix(k, "."+format) {
			sid := k[strings.LastIndex(k, "/")+1 : len(k)-len(format)-1]
			bySid[sid] = o
		}
	}
	var lat []float64
	var landed int64
	for _, s := range sessions {
		if !s.ok {
			continue
		}
		o, ok := bySid[s.callSid]
		if !ok {
			res.Missing++
			res.BytesLost += s.sent
			continue
		}
		res.Found++
		lat = append(lat, float64(o.modified.Sub(s.closedAt).Milliseconds()))
		got := o.size - 44
		if format == "mp3" {
			// CBR: bytes are proportional to duration. Compare durations
			// with a 2% + 0.2 s allowance for encoder delay and padding.
			bitrate := 64000.0 // LAME caps 8 kHz (MPEG-2.5) at 64 kbit/s
			if rate >= 16000 {
				bitrate = 128000
			}
			secsGot := float64(o.size) * 8 / bitrate
			secsSent := float64(s.sent) / float64(rate*4)
			if secsGot < secsSent*0.98-0.2 {
				res.Short++
				res.BytesLost += int64((secsSent - secsGot) * float64(rate*4))
			}
			landed += s.sent
			continue
		}
		if got < s.sent {
			res.Short++
			res.BytesLost += s.sent - got
		}
		landed += got
	}
	if len(lat) > 0 {
		sort.Float64s(lat)
		at := func(p float64) float64 { return lat[min(len(lat)-1, int(p*float64(len(lat))))] }
		res.LatencyMs = pcts{lat[0], at(0.50), at(0.95), at(0.99), lat[len(lat)-1]}
	}
	if res.Blast && res.SendSecs > 0 {
		res.IngestMBps = float64(landed) / 1e6 / res.SendSecs
	}
	if cleanup {
		var ids []types.ObjectIdentifier
		flush := func() {
			if len(ids) > 0 {
				client.DeleteObjects(ctx, &s3.DeleteObjectsInput{Bucket: &bucket, Delete: &types.Delete{Objects: ids, Quiet: aws.Bool(true)}})
				ids = nil
			}
		}
		for k := range found {
			ids = append(ids, types.ObjectIdentifier{Key: aws.String(k)})
			if len(ids) == 500 {
				flush()
			}
		}
		flush()
	}
}
