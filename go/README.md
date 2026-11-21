# upload-recordings in Go (proposal)

A Go implementation of the recording server, kept in its own directory so the
C++ service, its Debian packaging and its workflows are untouched. Nothing
here is built, packaged or published by CI. Whether it replaces the C++
service is a decision for the numbers in [BENCHMARKS.md](BENCHMARKS.md).

## Build and run

```bash
sudo apt install libmp3lame-dev        # the only native dependency
go build -o upload_recordings ./cmd/upload-recordings
go test -race ./...
```

The binary takes the same flags and environment as the C++ one, so the
existing `upload_recordings.service` unit starts it unchanged. At runtime it
needs `libmp3lame0` from Debian and nothing else: no libwebsockets, no AWS
C++ SDK, no bundled `.so` directory.

MP3 encoding uses LAME through cgo. There is no pure-Go encoder of comparable
quality, and using the same library with the same settings is what makes the
MP3 output byte-identical to the C++ service's. LAME comes from a Debian
package, so it does not bring back a from-source compile. `-tags nolame`
builds a cgo-free binary that serves WAV accounts only and says so in its log.

## The contract it implements

Taken from the C++ source at v1.9.3 and from how feature-server and mediajam
connect; checked against the running C++ binary by `bench/equivalence.sh`.

**Endpoint.** Plain HTTP on `--port` (default 3017). A websocket upgrade on
any path (feature-server uses `/record/<vendor>`) with subprotocol
`audio.jambonz.org` and HTTP Basic credentials matching `BASIC_AUTH_USERNAME`
/ `BASIC_AUTH_PASSWORD`. With either variable unset every connection is
refused. `GET` on any path starting with `/health` returns `200 OK`.

**Frames.** The first text message is the call metadata (JSON). Text is
accumulated until it parses as JSON, regardless of frame boundaries. Fields
read: `accountSid`, `callSid`, `sampleRate`, `direction`, `from`, `to`,
`applicationSid`, `originatingSipIp`, `fsSipAddress`. If none arrives within
`JAMBONZ_METADATA_TIMEOUT_SECS` (default 3) the session is written off and
everything else on the connection is ignored. Binary frames are raw 16-bit
little-endian interleaved **stereo** PCM. A later text message
`{"type":"session:summary","data":{...}}` is kept for `session.json`; `dtmf`
events and anything else are logged and ignored. The server never sends data.

**Account lookup.** One query per session:
`SELECT record_format, bucket_credential, eval_credential FROM accounts WHERE account_sid = ?`,
using `MYSQL_HOST`, `MYSQL_USER`, `MYSQL_DATABASE` and
`JAMBONES_MYSQL_PASSWORD` (falling back to `MYSQL_PASSWORD`). The database is
probed at startup and a failure is logged, not fatal. `bucket_credential` is
the api-server's `{"iv","content"}` AES-256-CBC envelope, keyed from
`ENCRYPTION_SECRET` (required).

**What is stored.** When the connection closes:

| Object | Key | Content type |
|---|---|---|
| recording | `YYYY/MM/DD/<callSid>.wav` or `.mp3` | S3: `binary/octet-stream`; Azure, Google: `application/octet-stream` |
| summary, if one was sent | `YYYY/MM/DD/<callSid>/session.json` | S3, Google: `application/json`; Azure: `application/octet-stream` |

The date is the server's local date at upload time. `record_format` `mp3`
gives MP3 (LAME, stereo, quality 2, 128 kbit/s requested, which LAME caps at
64 kbit/s for 8 kHz input); anything else gives WAV. S3 objects carry user
metadata `Account-Sid`, `Call-Sid`, `Direction`, `From`, `To`,
`Application-Sid`, `Originating-Sip-Id`, `Originating-Sip-Trunk-Name`,
`Sample-Rate`. `session.json` is the summary's `data` with `recording_key`
and `recording_started_at_ms` added.

**Storage vendors** (`vendor` in the credential):

- `aws_s3`: access key, secret, region.
- `s3_compatible`: the same plus `endpoint`. Always HTTPS, whatever scheme
  the endpoint carries. Path-style addressing for localhost and for hosts
  matching `S3_PATH_STYLE_SERVICES`. Region falls back to one parsed from an
  `s3.<region>.` endpoint.
- `azure`: connection string (`DefaultEndpointsProtocol=...;AccountName=...;AccountKey=...;EndpointSuffix=...`),
  SharedKey auth, Put Block in 4 MB blocks then Put Block List.
- `google`: service-account key, JWT bearer token, resumable upload in 8 MB chunks.

**Metrics.** statsd gauge `recording.sessions.count` (prefixed by
`JAMBONES_STATSD_PREFIX`) to `STATS_HOST`:`STATS_PORT` over UDP, or TCP when
`STATS_PROTOCOL=tcp`, on every session start and end. On EC2 with
`PutMetricData` permission, `RecordingSessionCount` in namespace
`Jambonz/Recording` every 30 s.

**Shutdown.** On SIGINT or SIGTERM it stops accepting, ends every live
session and exits once every recording in flight has been uploaded.

**Flags.** `--port`, `--threads` (sets GOMAXPROCS), `--aws-max-connections`
(concurrent uploads per storage host, default 64), `--max-buffer-size` (MB of
audio held before metadata is resolved, default 3), `-v`/`--version`,
`-h`/`--help`. `--buffer-process-size` and `-d` are accepted and ignored.

## Layout

| Path | What |
|---|---|
| `cmd/upload-recordings` | the server |
| `internal/server` | HTTP/websocket accept, the per-connection session, shutdown |
| `internal/wsproto` | the receive side of RFC 6455 |
| `internal/store` | S3, Azure and Google uploaders |
| `internal/audio` | WAV header, LAME binding |
| `internal/creds`, `internal/db`, `internal/summary`, `internal/metrics` | credential decryption, MySQL lookup, session.json stamping, statsd and CloudWatch |
| `cmd/loadgen`, `cmd/procmon`, `cmd/faultproxy`, `cmd/seed`, `cmd/equiv`, `bench/` | benchmark and equivalence tooling |
