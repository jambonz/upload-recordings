# Go vs C++ upload-recordings: benchmark report

Compares the Go implementation in this directory with the C++ service at tag
`v1.9.3`. This is a proposal; nothing here changes what is built or shipped.

## Conclusion

**Is the Go version more efficient? Yes on memory, on WAV CPU, and on
behaviour under storage trouble. No on MP3 CPU (equal). It is slower by about
100 ms to make a recording available at low load.**

| Measure | C++ v1.9.3 | Go | Verdict |
|---|---|---|---|
| Resident memory, 1000 live sessions | 989 MB | 92 MB | Go uses about a tenth. C++ costs about 1 MB per live session, Go about 0.08 MB |
| CPU, WAV, 1000 sessions x 60 s, 4 cores | 20.8 s | 13.3 s | Go 36% lower (16% to 40% lower across 10 to 1000 sessions) |
| CPU, WAV at 16 kHz, 500 sessions | 11.6 s | 11.2 s | equal |
| CPU, MP3, any load | 2.9 to 4.4 ms per audio second | 2.8 to 4.0 | equal within 3 to 10%: LAME dominates and both use the same library |
| Last frame to object stored, WAV | 6 to 17 ms p50 | 109 to 118 ms p50 | **Go is about 100 ms slower**, by design (see below) |
| Last frame to object stored, MP3, up to 500 sessions | 168 to 193 ms p50 | 271 to 301 ms p50 | **Go is about 100 ms slower** |
| Same, MP3, 1000 sessions on 4 cores (both saturated) | 5.2 s p50, 16.2 s p99 | 5.1 s p50, 13.1 s p99 | equal p50, Go better tail |
| Another tenant's storage is slow (20 s per upload) | healthy tenant loses 8 to 10% of its audio in all 50 calls | no loss | Go isolates tenants; C++ does not |
| Another tenant's storage stalls | healthy tenant loses 34% of its audio; its recordings appear 7 minutes late | no loss, 0.1 s | same cause |
| Recordings lost or short in normal load runs | 0 | 0 | equal |
| Ingest ceiling, 1 core | 1.7 GB/s | 2.8 GB/s | both far beyond any real load |
| Ingest ceiling, 4 cores | 2.1 GB/s (does not scale) | 5.8 GB/s (load generator limited) | Go scales, C++ does not, neither matters in practice |
| Cold start | 56 to 67 ms, or 5.1 s when the EC2 metadata probe has to time out | 11 to 13 ms | Go faster |
| Clean build | 223 s | 8 s | one run each |
| Binary | 44.7 MB plus 124 MB of bundled `.so` | 16.0 MB, links only libmp3lame and libc | |
| Container image | 1.29 GB | 123 MB | |

The strongest argument for the Go version is not raw efficiency. It is that
the C++ service drops audio from healthy calls when its worker pool is tied
up by slow uploads, and the Go version cannot do that by construction.

The argument against: at the loads jambonz.cloud runs today both services
are cheap on CPU. The saving that is real at any load is memory.

## Threading model of each

### C++ (from the code at v1.9.3)

- One libwebsockets/libev service thread accepts connections, reads sockets,
  parses frames, copies audio into a per-session in-memory buffer (under a
  per-session mutex) and parses JSON text frames.
- A boost::asio thread pool (`--threads`, default `hardware_concurrency()`)
  does everything else, serialised per session by a strand: the MySQL lookup
  and credential decrypt, flushing each 512 KB buffer to a temp file, and at
  hang-up `finalizeUpload()`, which encodes the MP3 (whole file) and then
  **blocks the worker until the upload finishes** (up to 600 s for S3; Azure
  and Google are synchronous curl).
- So at most `--threads` recordings can be encoding or uploading at once, and
  while they are, buffer flushes for live calls queue behind them. When a
  session's buffer passes `--max-buffer-size` (3 MB) the audio is dropped
  ("Buffer overflow: dropping data").

**On the belief that the single libwebsockets thread is the constraint: it
is partly right, and it is not the constraint that matters.** That thread
does carry 66 to 95% of the service's CPU in WAV runs, and total CPU in the
ingest-ceiling test never went meaningfully above one core however many cores
were available. But it is cheap: 1000 concurrent calls use about a third of
one core, so by extrapolation (not measured) it would saturate somewhere near
3,000 to 3,500 concurrent 8 kHz calls. The constraint that bites first is the
worker pool being blocked by uploads, which loses audio at 74 calls in the
slow-storage test.

Also: `hardware_concurrency()` ignores a cpuset. Under a 4-CPU limit the
service sized its pool at 12. The harness passes `--threads N` explicitly.

### Go

- `net/http` accept loop; one goroutine per connection, and that goroutine is
  the session from handshake to upload. The Go scheduler spreads sessions
  over `GOMAXPROCS` cores (`--threads` sets it; in the benchmarks it was set
  to the core limit explicitly).
- Audio goes socket to spool file through a 32 KB buffer. Nothing on that
  path is shared between sessions, so there is no lock on it.
- Each socket is read at most once every 200 ms (20 ms frames are coalesced).
  This cut ingest CPU nearly in half and is the cause of the 100 ms latency
  penalty: a hang-up is noticed on the next read.
- Memory per session is bounded: 16 KB read buffer, 32 KB spool buffer, and
  up to `--max-buffer-size` (3 MB) only while the metadata has not been
  resolved.
- When uploads fall behind: nothing is dropped. Audio is already on disk;
  finished calls wait for an upload connection (`--aws-max-connections`, 64
  per storage host). A slow tenant holds its own goroutines and spool files
  and nothing else. If the disk itself stalled, the session would stop
  reading and TCP backpressure would reach the sender.
- MP3 encoding happens after hang-up, limited to `GOMAXPROCS` at a time.
- Shared state, each touched once per session: the connection registry, the
  DB pool, the per-tenant storage client cache, the encode semaphore.

## Method

Everything ran in Docker Desktop on an Apple Silicon Mac: Linux arm64 VM,
12 CPUs, 6.2 GB RAM. Server under test pinned to CPUs 0-3 (0 to 0-7 in the
scaling suite), MinIO (TLS) and the fault proxy on 8-9, load generator and
MySQL 8.4 on 10-11. Fresh server process for every run. Both servers got the
same explicit `--threads N --aws-max-connections 64`.

- **Load generator** (`cmd/loadgen`): N websocket sessions the way
  feature-server and mediajam open them (subprotocol, basic auth, metadata,
  one 640-byte binary frame per 20 ms at 8 kHz stereo, dtmf, session:summary,
  close). Audio is synthetic two-party speech so LAME does real work. Starts
  are spread over a 10 s ramp. Afterwards it lists the bucket and checks
  every object exists and has the expected size.
- **Upload latency**: object `LastModified` minus the time the load generator
  closed that session. MinIO timestamps are what limit precision.
- **CPU and memory** (`cmd/procmon`): a sidecar in the server's PID
  namespace sampling `/proc`, including per-thread CPU.
- **Slow and failing storage** (`cmd/faultproxy`): a TLS reverse proxy in
  front of MinIO that throttles or fails PUTs for one tenant's bucket.
- **Repetitions**: main suite 3, scaling and 16 kHz 2, ingest ceiling 3,
  slow and stalled 2, cold start 5, failing storage 1, build time 1. Tables
  show median (min-max).

To reproduce: `bench/setup.sh`, `bench/equivalence.sh`, `bench/run.sh all`,
`python3 bench/report.py`. Raw per-run JSON is in `bench/raw/`.

### Limits of this benchmark

- A laptop VM, not a server; arm64, not amd64. Absolute numbers will differ.
  Ratios between the two implementations should hold.
- MinIO on the same machine: upload time is close to zero, which flatters
  both, and flatters C++ more (its workers are blocked for the upload).
- Only 6.2 GB RAM, so C++ at 1000 sessions used a sixth of the machine.
- Sessions all start within 10 s and all end within 10 s. That is a worst
  case for MP3 (every encode lands at once) and not how real traffic looks.
- The ingest-ceiling numbers are bounded by the load generator (2 cores) and
  the VM's disk, so the Go figures above 2 cores are a floor.

## Equivalence

`bench/equivalence.sh` plays 11 fixed sessions at both servers and compares
what lands in MinIO (`bench/raw/equivalence.txt`): 13 objects, 0 failures.

- WAV: byte-identical in every case (8 kHz, 16 kHz, odd byte count, audio
  before metadata with metadata split across frames, aborted TCP connection,
  large frames, no audio).
- MP3: byte-identical (same LAME, same settings). 8 kHz gives 8000 Hz stereo
  64 kbit/s; 16 kHz gives 16000 Hz stereo 128 kbit/s.
- S3 key, content type and user metadata identical.
- `session.json`: same members and values. Number formatting differs: C++
  rewrites `12.50` as `12.5`, Go preserves the sender's text.

Go unit and integration tests pass under `-race` on Linux.

## Multi-core scaling

1000 sessions, 30 s calls, full table below.

- **WAV**: neither needs a second core. C++ uses 0.36 to 0.38 of a core at
  every core count, with about 80% of it on the libwebsockets thread. Go uses
  0.19 to 0.25.
- **MP3**: both scale with cores, the same amount, because the work is LAME
  and both run N encodes at once. p50 latency for 1000 simultaneous hang-ups:
  28 s on 1 core, 10 s on 2, 2 s on 4, 0.1 to 0.2 s on 8, for both.
- **Saturation**: MP3 encoding costs about 2.9 CPU ms per second of 8 kHz
  audio (6.3 ms at 16 kHz), so one core sustains roughly 340 concurrent
  8 kHz MP3 calls in steady state, in either implementation. For WAV the Go
  figure is 0.22 ms per audio second, about 4,500 calls per core; these are
  extrapolations from the measured cost, not measured limits.
- **Per-thread**: in the C++ ingest-ceiling runs peak CPU stayed at 85 to
  108% from 1 to 8 cores (one outlier at 194%) and throughput went from 1.7
  to 2.1 GB/s. Go went from 2.8 to 5.8 GB/s at 4 cores, where the load
  generator ran out.

## Storage trouble

**Slow.** Tenant A's uploads take 20 s each (24 calls). Tenant B has 50 calls
of 150 s on a healthy bucket. C++: A's uploads queue four at a time (p50
80 s, max 120 s), and while they hold the pool, B's buffers overflow: all 50
of B's recordings are short, 20 to 25 MB of 240 MB lost, 30,000+ "dropping"
log lines. Go: A's recordings take 20 s each, B loses nothing.

**Stalled.** Same with uploads that never complete in time. Both give up on
A's uploads and A's 24 recordings are lost in both (Go: 60 s wait for a
response, 3 attempts; the C++ failure reason was not captured). C++: B loses
83 MB of 240 MB and its recordings appear 7 minutes after the calls ended.
Go: B unaffected.

**Failing (503).** Both log 100 errors, lose 100 recordings, leave no spool
files and carry on serving a healthy tenant. Neither keeps a recording for a
later retry when the upload fails. That is existing behaviour, not something
the port changes.

## Where the Go version is worse or riskier

- About 100 ms later to store each recording (up to 200 ms worst case).
- It is new code. The C++ service has production history; this has tests.
- It keeps a cgo dependency on libmp3lame (Debian package). There is no
  pure-Go MP3 encoder of comparable quality. `-tags nolame` builds without
  cgo and serves WAV accounts only.

## Not ported

- **Call evaluation** (eval notifier for Roark/Coval, the GCS presigner, the
  Coval mapper) and its InfluxDB alert. The Go server logs a warning when an
  account has `eval_credential` set. This is the main gap to close before any
  switch.
- `-s` (TLS with the test certificate): exits with an error.
- `-d` and `--buffer-process-size`: accepted and ignored.

## Not tested

- Azure and Google uploads against the real services (unit tests against
  fake servers only). AWS S3 itself (MinIO only).
- CloudWatch metrics (not on EC2), statsd over TCP.
- amd64. Real feature-server or mediajam as the client (the load generator
  imitates them; the Go tests also use the websocket library mediajam uses).
- Soak: nothing ran longer than a few minutes.
- Debian packaging and the systemd unit (deliberately untouched).

## Behaviour found in the C++ service

Replicated in Go, so the outputs match:

- The WAV header always says 8000 Hz stereo 16-bit, whatever `sampleRate`
  is. A 16 kHz WAV recording plays at half speed.
- The `Account-Sid` object metadata is always empty.
- The API server's legacy `aes-256-ctr` credential format is not supported.

Different in Go:

- Wrong credentials or subprotocol: C++ drops the connection with no HTTP
  response; Go answers 401 or 400.
- `recording_started_at_ms`: C++ misparses the fraction (`.055` becomes
  550 ms); Go parses it correctly.
- Metadata without `sampleRate`: C++ uses an uninitialised value; Go uses 0.
- The S3 client cache key omits the secret in C++, so a rotated secret keeps
  using the old client until restart; Go includes it.
- C++ blocks for 5 s at startup off EC2 while probing instance metadata; Go
  probes in the background.
- Under bursts C++ drops audio (see above); Go does not.

Not examined further: C++ never finalises a zero-byte Google upload, and its
Azure resource path depends on the hostname ending in `.net`.

## Raw tables

Columns: CPU s is total process CPU for the run. "Busiest thread" is the
share of that CPU spent on the single busiest thread. "Sender lag" is how
late the load generator ever was with a frame (0 means the load was real
time). One Go ingest-ceiling run at 4 cores shows 49% lost: MinIO ran out of
disk and answered 507 (reproduced and confirmed in the server log), so that
row's "stored" range is a harness artefact.

### Main: 4 cores, 8 kHz stereo, 60 s calls

| format | sessions | impl | runs | CPU s | CPU ms per audio s | peak CPU % | RSS median MB | RSS peak MB | latency p50 ms | p99 ms | max ms | missing / short / errors | audio lost MB | sender lag max ms | busiest thread % of CPU |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| mp3 | 10 | cpp | 3 | 2.6 (2.4-2.8) | 4.43 (4.08-4.56) | 34 (32-36) | 43 (43-43) | 51 (48-52) | 185 (180-199) | 206 (197-209) | 206 (197-209) | 0 / 0 / 0 | 0.0 | 0 | 32 (30-34) |
| mp3 | 10 | go | 3 | 2.4 (2.2-2.5) | 3.98 (3.78-4.12) | 26 (21-36) | 17 (17-20) | 23 (23-23) | 271 (253-304) | 383 (368-402) | 383 (368-402) | 0 / 0 / 0 | 0.0 | 0 | 38 (36-53) |
| mp3 | 100 | cpp | 3 | 19.4 (19.4-19.5) | 3.24 (3.20-3.24) | 138 (135-139) | 176 (141-245) | 183 (152-251) | 168 (166-169) | 221 (218-276) | 221 (218-276) | 0 / 0 / 0 | 0.0 | 0 | 29 (28-29) |
| mp3 | 100 | go | 3 | 19.2 (19.0-19.5) | 3.16 (3.16-3.18) | 129 (122-161) | 25 (25-25) | 37 (37-38) | 280 (271-282) | 430 (393-563) | 430 (393-563) | 0 / 0 / 0 | 0.0 | 0 | 22 (19-24) |
| mp3 | 500 | cpp | 3 | 89.4 (88.6-90.3) | 2.99 (2.97-3.03) | 392 (390-392) | 551 (497-600) | 582 (534-630) | 193 (184-204) | 612 (414-911) | 642 (421-1419) | 0 / 0 / 0 | 0.0 | 0 | 24 (24-24) |
| mp3 | 500 | go | 3 | 87.6 (87.2-88.7) | 2.93 (2.90-2.93) | 399 (389-400) | 55 (52-57) | 88 (84-90) | 301 (291-321) | 607 (532-800) | 652 (610-858) | 0 / 0 / 0 | 0.0 | 0 | 14 (13-14) |
| mp3 | 1000 | cpp | 3 | 177.0 (176.3-178.0) | 2.94 (2.94-2.96) | 394 (393-394) | 1004 (966-1023) | 1060 (1024-1070) | 5172 (5094-5481) | 16199 (16138-16622) | 16788 (16457-17263) | 0 / 0 / 0 | 0.0 | 0 | 23 (23-23) |
| mp3 | 1000 | go | 3 | 170.9 (169.5-171.7) | 2.84 (2.83-2.87) | 400 (399-400) | 93 (84-94) | 154 (143-155) | 5063 (5032-5294) | 13081 (12885-13504) | 13251 (13001-13655) | 0 / 0 / 0 | 0.0 | 0 | 12 (12-13) |
| wav | 10 | cpp | 3 | 1.0 (0.9-1.0) | 1.55 (1.51-1.67) | 2 (2-3) | 41 (40-57) | 44 (43-59) | 17 (16-20) | 20 (20-24) | 20 (20-24) | 0 / 0 / 0 | 0.0 | 0 | 95 (95-96) |
| wav | 10 | go | 3 | 0.6 (0.6-0.6) | 1.00 (0.97-1.04) | 2 (2-2) | 19 (18-20) | 21 (21-21) | 109 (84-133) | 211 (186-212) | 211 (186-212) | 0 / 0 / 0 | 0.0 | 0 | 21 (19-24) |
| wav | 100 | cpp | 3 | 3.8 (3.7-4.2) | 0.64 (0.61-0.69) | 8 (8-8) | 184 (146-207) | 190 (153-219) | 13 (13-14) | 23 (22-25) | 23 (22-25) | 0 / 0 / 0 | 0.0 | 0 | 78 (77-81) |
| wav | 100 | go | 3 | 3.2 (3.2-3.2) | 0.53 (0.52-0.54) | 7 (6-7) | 25 (25-27) | 31 (31-33) | 118 (110-123) | 211 (210-212) | 211 (210-212) | 0 / 0 / 0 | 0.0 | 0 | 21 (20-22) |
| wav | 500 | cpp | 3 | 13.1 (10.4-13.5) | 0.44 (0.35-0.45) | 22 (18-23) | 539 (509-590) | 570 (533-605) | 9 (8-9) | 30 (22-45) | 138 (116-185) | 0 / 0 / 0 | 0.0 | 0 | 79 (76-81) |
| wav | 500 | go | 3 | 9.9 (8.3-9.9) | 0.33 (0.28-0.33) | 17 (15-19) | 57 (51-57) | 85 (79-85) | 112 (108-112) | 211 (211-227) | 272 (219-288) | 0 / 0 / 0 | 0.0 | 0 | 20 (19-20) |
| wav | 1000 | cpp | 3 | 20.8 (20.7-22.0) | 0.35 (0.34-0.37) | 36 (36-38) | 989 (968-1025) | 1029 (1013-1068) | 6 | 28 (22-81) | 99 (97-135) | 0 / 0 / 0 | 0.0 | 0 | 80 (80-82) |
| wav | 1000 | go | 3 | 13.3 (13.1-13.6) | 0.22 (0.22-0.23) | 25 (25-26) | 92 (82-94) | 137 (131-137) | 109 (107-112) | 206 (205-206) | 276 (247-295) | 0 / 0 / 0 | 0.0 | 0 | 20 (18-20) |

### 16 kHz stereo, 500 sessions, 4 cores, 60 s calls

| format | sessions | impl | runs | CPU s | CPU ms per audio s | peak CPU % | RSS median MB | RSS peak MB | latency p50 ms | p99 ms | max ms | missing / short / errors | audio lost MB | sender lag max ms | busiest thread % of CPU |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| mp3 | 500 | cpp | 2 | 188.1 (186.6-189.6) | 6.31 (6.30-6.31) | 396 (396-396) | 478 (472-483) | 501 (494-509) | 7637 (7357-7917) | 21294 (21139-21448) | 21682 (21570-21794) | 0 / 0 / 0 | 0.0 | 0 | 25 (24-25) |
| mp3 | 500 | go | 2 | 190.0 (189.8-190.2) | 6.33 (6.32-6.33) | 400 (400-401) | 55 (53-57) | 92 (90-93) | 7618 (7291-7944) | 18464 (18184-18745) | 18671 (18407-18935) | 0 / 0 / 0 | 0.0 | 0 | 13 (13-13) |
| wav | 500 | cpp | 2 | 11.6 (11.5-11.8) | 0.39 (0.38-0.40) | 19 (19-19) | 486 (481-491) | 514 (508-520) | 14 (13-14) | 30 (28-31) | 102 (95-109) | 0 / 0 / 0 | 0.0 | 0 | 66 (66-66) |
| wav | 500 | go | 2 | 11.2 (11.2-11.2) | 0.37 (0.37-0.38) | 20 (19-21) | 56 (55-57) | 82 (82-82) | 116 (110-121) | 216 (216-217) | 284 (277-290) | 0 / 0 / 0 | 0.0 | 0 | 18 (17-19) |

### Scaling: 1000 sessions, 30 s calls, 1/2/4/8 cores

| format | cores | impl | runs | CPU s | CPU ms per audio s | peak CPU % | RSS median MB | RSS peak MB | latency p50 ms | p99 ms | max ms | missing / short / errors | audio lost MB | sender lag max ms | busiest thread % of CPU |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| mp3 | 1 | cpp | 2 | 88.4 (88.0-88.8) | 2.95 (2.93-2.97) | 99 (99-99) | 997 (997-998) | 1002 (1001-1004) | 28494 (28057-28932) | 66172 (66054-66289) | 66837 (66668-67006) | 0 / 0 / 0 | 0.0 | 0 | 91 (91-91) |
| mp3 | 1 | go | 2 | 84.5 (84.4-84.7) | 2.82 (2.81-2.83) | 101 (101-101) | 69 (69-70) | 134 (134-134) | 28268 (27966-28570) | 60420 (60213-60628) | 60711 (60476-60946) | 0 / 0 / 0 | 0.0 | 0 | 63 (55-70) |
| mp3 | 2 | cpp | 2 | 89.2 (89.1-89.3) | 2.96 (2.95-2.97) | 195 (195-195) | 954 (947-961) | 999 (995-1002) | 10606 (10487-10725) | 25601 (25393-25809) | 26459 (26190-26728) | 0 / 0 / 0 | 0.0 | 0 | 46 (46-46) |
| mp3 | 2 | go | 2 | 85.7 (85.4-86.0) | 2.86 (2.85-2.86) | 201 (201-201) | 74 (71-77) | 146 (145-148) | 10189 (10003-10375) | 22653 (22392-22914) | 22785 (22511-23059) | 0 / 0 / 0 | 0.0 | 0 | 22 (21-23) |
| mp3 | 4 | cpp | 2 | 90.0 (89.3-90.8) | 3.00 (2.98-3.01) | 387 (387-388) | 715 (710-721) | 946 (931-961) | 2064 (2049-2079) | 6404 (6294-6514) | 6716 (6521-6912) | 0 / 0 / 0 | 0.0 | 0 | 23 (23-23) |
| mp3 | 4 | go | 2 | 86.5 (86.1-86.8) | 2.89 (2.88-2.90) | 400 (400-400) | 93 (92-94) | 147 (147-148) | 2078 (1991-2165) | 4658 (4601-4714) | 4735 (4685-4785) | 0 / 0 / 0 | 0.0 | 0 | 13 (13-14) |
| mp3 | 8 | cpp | 2 | 93.1 (91.7-94.5) | 3.11 (3.08-3.15) | 748 (740-756) | 679 (672-686) | 944 (925-963) | 94 (90-97) | 270 (247-292) | 410 (357-463) | 0 / 0 / 0 | 0.0 | 0 | 12 (12-12) |
| mp3 | 8 | go | 2 | 91.3 (90.8-91.7) | 3.06 (3.04-3.08) | 780 (772-788) | 94 (90-99) | 155 (153-157) | 209 (206-212) | 397 (383-411) | 486 (435-537) | 0 / 0 / 0 | 0.0 | 0 | 8 (8-9) |
| wav | 1 | cpp | 2 | 10.7 (10.7-10.7) | 0.36 (0.36-0.36) | 36 (35-37) | 665 (648-682) | 866 (858-875) | 4 (3-4) | 23 | 96 (65-127) | 0 / 0 / 0 | 0.0 | 0 | 80 (80-80) |
| wav | 1 | go | 2 | 5.8 (5.7-5.9) | 0.19 (0.19-0.20) | 19 (18-19) | 88 (86-90) | 129 (129-129) | 104 | 203 (202-204) | 250 (242-259) | 0 / 0 / 0 | 0.0 | 0 | 70 (60-81) |
| wav | 2 | cpp | 2 | 11.0 (11.0-11.0) | 0.37 (0.37-0.37) | 37 (36-37) | 664 (658-669) | 883 (880-886) | 4 (3-4) | 12 (10-15) | 38 (32-44) | 0 / 0 / 0 | 0.0 | 0 | 78 (78-79) |
| wav | 2 | go | 2 | 6.7 (6.7-6.8) | 0.22 (0.22-0.23) | 22 (21-22) | 88 (86-90) | 124 (123-126) | 106 (105-106) | 203 | 216 (210-221) | 0 / 0 / 0 | 0.0 | 0 | 27 (26-27) |
| wav | 4 | cpp | 2 | 11.5 (11.1-11.8) | 0.38 (0.37-0.39) | 38 (36-40) | 681 (669-693) | 888 (880-897) | 3 | 10 (10-11) | 122 (117-127) | 0 / 0 / 0 | 0.0 | 0 | 78 (77-78) |
| wav | 4 | go | 2 | 7.4 (7.2-7.6) | 0.25 (0.24-0.25) | 25 (23-26) | 93 (91-95) | 142 (141-143) | 105 (104-106) | 203 | 214 (213-216) | 0 / 0 / 0 | 0.0 | 0 | 20 (20-21) |
| wav | 8 | cpp | 2 | 11.5 (11.4-11.5) | 0.38 (0.38-0.38) | 38 (37-38) | 672 (659-684) | 891 (885-896) | 3 | 12 (12-13) | 80 (52-107) | 0 / 0 / 0 | 0.0 | 0 | 78 (78-79) |
| wav | 8 | go | 2 | 7.6 (7.5-7.7) | 0.25 (0.25-0.26) | 25 (24-25) | 91 (91-91) | 129 (129-129) | 101 (97-105) | 204 (204-205) | 246 (214-277) | 0 / 0 / 0 | 0.0 | 0 | 13 (13-13) |

### Ingest ceiling: 8 connections sending as fast as the server reads, 1 s

| cores | impl | runs | accepted MB/s | stored MB/s | audio lost % | stored rate as 8 kHz calls | peak CPU % | RSS peak MB | busiest thread % of CPU |
|---|---|---|---|---|---|---|---|---|---|
| 1 | cpp | 3 | 1719 (1373-1760) | 1718 (1372-1759) | 0.1 (0.0-0.1) | 53695 (42875-54954) | 85 (84-85) | 267 (236-275) | 36 (33-39) |
| 1 | go | 3 | 2838 (2282-2849) | 2838 (2282-2849) | 0.0 | 88699 (71310-89032) | 66 (65-67) | 20 (19-21) | 47 (31-48) |
| 2 | cpp | 3 | 1887 (1816-1985) | 1883 (1816-1985) | 0.0 (0.0-0.2) | 58835 (56736-62018) | 91 (90-95) | 459 (454-465) | 34 (33-34) |
| 2 | go | 3 | 3856 (2106-4380) | 3856 (2106-4380) | 0.0 | 120492 (65817-136889) | 107 (105-109) | 20 (20-21) | 25 (20-36) |
| 4 | cpp | 3 | 2054 (2045-2086) | 2054 (2045-2086) | 0.0 (0.0-0.0) | 64182 (63911-65177) | 101 (100-102) | 454 (450-456) | 32 (32-33) |
| 4 | go | 3 | 5786 (4956-5998) | 4956 (3034-5786) | 0.0 (0.0-49.4) | 154879 (94800-180827) | 188 (181-190) | 21 (20-23) | 17 (17-22) |
| 8 | cpp | 3 | 2144 (2022-2153) | 2144 (2021-2153) | 0.0 (0.0-0.0) | 66994 (63152-67279) | 108 (106-194) | 453 (444-454) | 30 (24-31) |
| 8 | go | 3 | 4069 (3632-5833) | 4069 (3632-5833) | 0.0 | 127146 (113505-182293) | 185 (124-214) | 23 (22-24) | 20 (19-23) |

### Slow storage for one tenant (uploads take 20 s)

| impl | run | tenant | stored | missing | short | audio lost MB | latency p50 s | max s | server RSS peak MB | 'dropping' log lines |
|---|---|---|---|---|---|---|---|---|---|---|
| cpp | 1 | A (slow bucket, 24 x 10 s) | 24 | 0 | 0 | 0.0 of 7.7 | 79.6 | 119.7 | 216 | 30651 |
| cpp | 1 | B (healthy bucket, 50 x 150 s) | 50 | 0 | 50 | 19.6 of 240.0 | 0.0 | 0.0 | 216 | 30651 |
| go | 1 | A (slow bucket, 24 x 10 s) | 24 | 0 | 0 | 0.0 of 7.7 | 20.1 | 20.1 | 28 | 0 |
| go | 1 | B (healthy bucket, 50 x 150 s) | 50 | 0 | 0 | 0.0 of 240.0 | 0.1 | 0.2 | 28 | 0 |
| cpp | 2 | A (slow bucket, 24 x 10 s) | 24 | 0 | 0 | 0.0 of 7.7 | 79.6 | 119.4 | 250 | 38729 |
| cpp | 2 | B (healthy bucket, 50 x 150 s) | 50 | 0 | 50 | 24.8 of 240.0 | 0.0 | 0.0 | 250 | 38729 |
| go | 2 | A (slow bucket, 24 x 10 s) | 24 | 0 | 0 | 0.0 of 7.7 | 20.1 | 20.1 | 29 | 0 |
| go | 2 | B (healthy bucket, 50 x 150 s) | 50 | 0 | 0 | 0.0 of 240.0 | 0.2 | 0.2 | 29 | 0 |

### Stalled storage for one tenant (uploads time out)

| impl | run | tenant | stored | missing | short | audio lost MB | latency p50 s | max s | server RSS peak MB | 'dropping' log lines |
|---|---|---|---|---|---|---|---|---|---|---|
| cpp | 1 | A (stalled bucket, 24 x 10 s) | 0 | 24 | 0 | 7.7 of 7.7 | 0.0 | 0.0 | 225 | 129300 |
| cpp | 1 | B (healthy bucket, 50 x 150 s) | 50 | 0 | 50 | 82.7 of 240.0 | 434.8 | 462.6 | 225 | 129300 |
| go | 1 | A (stalled bucket, 24 x 10 s) | 0 | 24 | 0 | 7.7 of 7.7 | 0.0 | 0.0 | 34 | 0 |
| go | 1 | B (healthy bucket, 50 x 150 s) | 50 | 0 | 0 | 0.0 of 240.0 | 0.1 | 0.2 | 34 | 0 |
| cpp | 2 | A (stalled bucket, 24 x 10 s) | 0 | 24 | 0 | 7.7 of 7.7 | 0.0 | 0.0 | 255 | 129300 |
| cpp | 2 | B (healthy bucket, 50 x 150 s) | 50 | 0 | 50 | 82.7 of 240.0 | 440.2 | 440.5 | 255 | 129300 |
| go | 2 | A (stalled bucket, 24 x 10 s) | 0 | 24 | 0 | 7.7 of 7.7 | 0.0 | 0.0 | 33 | 0 |
| go | 2 | B (healthy bucket, 50 x 150 s) | 50 | 0 | 0 | 0.0 of 240.0 | 0.2 | 0.2 | 33 | 0 |

### Storage answering 503

| impl | recordings lost | upload errors logged | spool files left | healthy tenant stored afterwards | RSS peak MB | CPU s |
|---|---|---|---|---|---|---|
| cpp | 100 of 100 | 100 | 0 | 20 of 20 | 108 | 1.8 |
| go | 100 of 100 | 100 | 0 | 20 of 20 | 33 | 1.6 |

### Cold start

| impl | runs | ms to accepting connections |
|---|---|---|
| cpp | 5 | 61 (56-5092); all: 5092, 61, 67, 58, 56 |
| go | 5 | 12 (11-13); all: 13, 12, 13, 11, 11 |

